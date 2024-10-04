package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/likexian/doh"
	"github.com/likexian/doh/dns"

	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/ssh"
)

var (
	b32encoder = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base64.NoPadding)

	domain           = flag.String("domain", "srv.us", "Domain name under which we run")
	sshPort          = flag.Int("ssh-port", 22, "Port for SSH to bind to")
	httpsPort        = flag.Int("https-port", 443, "Port for HTTPS to bind to")
	httpsChainPath   = flag.String("https-chain-path", "/etc/letsencrypt/live/srv.us/fullchain.pem", "Path to the certificate chain")
	httpsKeyPath     = flag.String("https-key-path", "/etc/letsencrypt/live/srv.us/privkey.pem", "Path to the private key")
	sshHostKeysPath  = flag.String("ssh-host-keys-path", "/etc/ssh", "Path where ssh_host_ecdsa_key, ssh_host_ed25519_key, ssh_host_rsa_key can be found")
	githubSubdomains = flag.Bool("github-subdomains", true, "Whether to expose $username.gh subdomains")
	gitlabSubdomains = flag.Bool("gitlab-subdomains", true, "Whether to expose $username.gl subdomains")
	pgConn           = flag.String("pg-conn", "", "Postgres connection string")
)

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type target struct {
	KeyID  string
	Remote *ssh.ServerConn
	Host   string
	Port   uint32
}

type void struct{}

var v void

type tunnelRef struct {
	Endpoint string
	Target   *target
}

type sshConnection struct {
	KeyID      string
	Sessions   map[ssh.Channel]void
	TunnelRefs map[*tunnelRef]void
	lastPort   uint16
}

type server struct {
	sync.Mutex
	conns     map[*ssh.ServerConn]*sshConnection
	endpoints map[string]map[*target]void
	pool      *pgxpool.Pool
	dns       *doh.DoH
}

func newServer(pool *pgxpool.Pool) *server {
	return &server{
		conns:     map[*ssh.ServerConn]*sshConnection{},
		endpoints: map[string]map[*target]void{},
		pool:      pool,
		dns:       doh.Use(doh.GoogleProvider, doh.CloudflareProvider),
	}
}

func (s *server) startSession(keyID string, conn *ssh.ServerConn, ch ssh.Channel) {
	s.Lock()
	defer s.Unlock()

	if _, found := s.conns[conn]; !found {
		s.conns[conn] = newConnection(keyID, ch)
	} else {
		s.conns[conn].Sessions[ch] = v
	}
}

func (s *server) newPort(conn *ssh.ServerConn) uint16 {
	s.Lock()
	defer s.Unlock()

	s.conns[conn].lastPort++
	return s.conns[conn].lastPort
}

// A lock is required
func (s *server) insertEndpointTarget(endpoint string, t *target) {
	log.Printf("%s(%s) on %s", t.Remote.RemoteAddr(), t.KeyID, endpoint)

	if s.endpoints[endpoint] != nil {
		s.endpoints[endpoint][t] = v
	} else {
		s.endpoints[endpoint] = map[*target]void{t: v}
	}
	sConn := s.conns[t.Remote]
	sConn.TunnelRefs[&tunnelRef{
		Endpoint: endpoint,
		Target:   t,
	}] = v
}

// A lock is required
func (s *server) removeEndpointTarget(endpoint string, t *target) {
	log.Printf("%s(%s) off %s", t.Remote.RemoteAddr(), t.KeyID, endpoint)

	if s.endpoints[endpoint] == nil {
		return
	}

	delete(s.endpoints[endpoint], t)
	if len(s.endpoints[endpoint]) == 0 {
		delete(s.endpoints, endpoint)
	}

	sConn := s.conns[t.Remote]
	delete(sConn.TunnelRefs, &tunnelRef{
		Endpoint: endpoint,
		Target:   t,
	})
}

func (s *server) pickTarget(endpoint string) *target {
	s.Lock()
	ep, found := s.endpoints[endpoint]
	s.Unlock()

	if !found {
		resp, err := s.dns.Query(context.Background(), dns.Domain(endpoint), "CNAME")
		if err != nil {
			log.Printf("Could not resolve %s (%v)", endpoint, err)
			return nil
		}

		s.Lock()
		for _, rec := range resp.Answer {
			host := strings.TrimSuffix(rec.Data, ".")
			ep, found = s.endpoints[host]
			if found {
				break
			}
		}
		s.Unlock()
	}

	if !found {
		return nil
	} else {
		var candidates []*target
		for c := range ep {
			candidates = append(candidates, c)
		}
		return candidates[rand.Intn(len(candidates))]
	}
}

func newConnection(keyID string, ch ssh.Channel) *sshConnection {
	return &sshConnection{
		KeyID:      keyID,
		Sessions:   map[ssh.Channel]void{ch: v},
		TunnelRefs: map[*tunnelRef]void{},
		lastPort:   0,
	}
}

func (s *server) endSession(conn *ssh.ServerConn, ch ssh.Channel) {
	reportStatus(ch, 0)
	if err := ch.Close(); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("Could not end SSH session (%v)", err)
	}

	s.Lock()
	defer s.Unlock()

	c := s.conns[conn]
	if c == nil {
		return
	}
	delete(c.Sessions, ch)

	if len(c.Sessions) == 0 {
		go func() {
			_ = conn.Close()
		}()
	}
}

func (s *server) closeConnection(conn *ssh.ServerConn) {
	s.Lock()
	defer s.Unlock()

	sConn, found := s.conns[conn]
	if !found {
		return
	}
	for er := range sConn.TunnelRefs {
		s.removeEndpointTarget(er.Endpoint, er.Target)
	}
	delete(s.conns, conn)
	go func() {
		_ = conn.Close()
		log.Printf("%s(%s) disconnected", conn.RemoteAddr(), sConn.KeyID)
	}()
}

func (s *server) serveHTTPS() {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(*httpsPort))
	if err != nil {
		log.Fatalln(err)
	}

	defer func() {
		err := listener.Close()
		if err != nil {
			log.Printf("Could not close HTTPS listener (%v)", err)
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept HTTPS connection (%s)", err)
			continue
		}

		go s.serveHTTPSConnection(conn)
	}
}

func (s *server) serveHTTPSConnection(raw net.Conn) {
	name := ""

	cert, err := tls.LoadX509KeyPair(*httpsChainPath, *httpsKeyPath)
	if err != nil {
		log.Println(err)
	}

	c := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(i *tls.ClientHelloInfo) (*tls.Config, error) {
			name = i.ServerName
			return nil, nil
		},
		NextProtos: []string{
			"http/1.1",
		},
	}

	https := tls.Server(raw, c)

	defer func() {
		_ = https.Close()
	}()

	if err := https.Handshake(); err != nil {
		return
	}

	if name == *domain {
		err = s.serveRoot(https)
		if err != nil {
			log.Printf("root failed (%v)", err)
		}
		return
	}

	tgt := s.pickTarget(name)
	if tgt == nil {
		_ = httpErrorOut(https, "503 Service Unavailable", "No tunnel available.")
		return
	}

	sshChannel, reqs, err := tgt.Remote.OpenChannel("forwarded-tcpip", ssh.Marshal(&remoteForwardChannelData{
		DestAddr:   tgt.Host,
		DestPort:   tgt.Port,
		OriginAddr: *domain,
		OriginPort: uint32(s.newPort(tgt.Remote)),
	}))

	if err != nil {
		_ = httpErrorOut(https, "502 Bad Gateway", err.Error())
		return
	}

	defer func() {
		if err := sshChannel.Close(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s→%v channel close failed (%d)", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), err)
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	go func() {
		b, err := io.Copy(https, sshChannel)
		log.Printf("%v:%s→%v xfer %d", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), b)
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s→%v copy failed (%v)", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), err)
		}
		if err := https.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s→%v close failed (%v)", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), err)
		}
		wg.Done()
	}()

	go func() {
		b, err := io.Copy(sshChannel, https)
		log.Printf("%v:%s←%v xfer %d", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), b)
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s←%v copy failed (%v)", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), err)
		}
		if err := sshChannel.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s←%v close failed (%v)", tgt.Remote.RemoteAddr(), name, raw.RemoteAddr(), err)
		}
		wg.Done()
	}()

	wg.Wait()
}

func (s *server) serveRoot(https *tls.Conn) error {
	r := bufio.NewReader(https)
	req, err := http.ReadRequest(r)
	if err != nil {
		return fmt.Errorf("could not read request: %w", err)
	}
	if req.URL.Path == "/echo" {
		defer func() {
			_ = req.Body.Close()
		}()
		ct := req.Header.Get("Content-Type")
		if ct == "" {
			ct = "text/plain"
		}
		_, _ = https.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n", ct)))
		_, _ = io.Copy(https, req.Body)
	} else if req.URL.Path == "/h" {
		defer func() {
			_ = req.Body.Close()
		}()
		_, _ = https.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\n"))
		_ = req.Header.Write(https)
	} else if req.URL.Path == "/d" {
		defer func() {
			_ = req.Body.Close()
		}()
		_, _ = https.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><script>document.body.innerHTML = decodeURI(window.location.hash.substring(1))</script></body></html>"))
	} else if req.URL.Path == "/tarpit" {
		_, _ = https.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"))
		for {
			if _, err = https.Write([]byte(".")); err != nil {
				return nil
			}
			time.Sleep(1 * time.Second)
		}
	} else if strings.HasPrefix(req.URL.Path, "/r/") {
		_, _ = https.Write([]byte(fmt.Sprintf("HTTP/1.1 307 Temporary Redirect\r\nLocation: /r/%v\r\n\r\n", uuid.New())))
	} else if req.Method == "POST" {
		defer func() {
			_ = req.Body.Close()
		}()
		content, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("could not read request body: %w", err)
		}
		hash := sha1.Sum(content)
		code := b32encoder.EncodeToString(hash[:])
		rows, _ := s.pool.Query(context.Background(), "INSERT INTO pastes(code, content) VALUES ($1, $2) ON CONFLICT DO NOTHING", code, content)
		if rows != nil {
			rows.Close()
		}
		_, _ = https.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n\r\nhttps://%s/%s\r\n", *domain, code)))
	} else if req.URL.Path == "/" {
		_, _ = https.Write([]byte("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://docs.srv.us\r\n\r\n"))
	} else {
		code := req.URL.Path[1:]
		res, _ := s.pool.Query(context.Background(), "SELECT content FROM pastes WHERE code = $1", code)
		if res != nil {
			defer res.Close()
			if res.Next() {
				cols, err := res.Values()
				if err != nil {
					_, _ = https.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
					return fmt.Errorf("could not read paste: %w", err)
				}
				content := cols[0].([]byte)
				_, _ = https.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n\r\n%s", content)))
			} else {
				_, _ = https.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
			}
		}
	}
	return nil
}

func httpErrorOut(conn net.Conn, status string, message string) error {
	r := bufio.NewReader(conn)
	if _, err := http.ReadRequest(r); err != nil {
		return err
	}
	_, err := conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %s\r\nContent-Length: %d\r\n\r\n%s", status, len(message), message)))
	return err
}

func (s *server) serveSSH() {
	sshConfig := ssh.ServerConfig{
		ServerVersion: "SSH-2.0-" + *domain + "-1.0",
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "Usage: ssh " + *domain + " -R 1:localhost:3000 -R 2:192.168.0.1:80 …\r\nIf you get a Permission denied error, first generate a key with ssh-keygen -t ed25519\r\n"
		},
	}
	addKey(&sshConfig, *sshHostKeysPath+"/ssh_host_ecdsa_key")
	addKey(&sshConfig, *sshHostKeysPath+"/ssh_host_ed25519_key")
	addKey(&sshConfig, *sshHostKeysPath+"/ssh_host_rsa_key")

	listener, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(*sshPort))
	if err != nil {
		log.Fatalf("Failed to listen on port %d (%s)", *sshPort, err)
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept (%s)", err)
		} else {
			go s.serveSSHConnection(&sshConfig, &tcpConn)
		}
	}
}

func (s *server) serveSSHConnection(sshConfig *ssh.ServerConfig, tcpConn *net.Conn) {
	var key *ssh.PublicKey
	config := sshConfig
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		key = &k
		return &ssh.Permissions{}, nil
	}

	conn, newChans, reqs, err := ssh.NewServerConn(*tcpConn, config)
	if key == nil || err != nil {
		return
	}

	keyID := base64.RawStdEncoding.EncodeToString((*key).Marshal()[:])

	githubEnabled := false
	if *githubSubdomains && conn.User() != "nomatch" {
		githubEnabled = keyMatchesAccount("github.com", conn.User(), keyID)
	}
	gitlabEnabled := false
	if *gitlabSubdomains && conn.User() != "nomatch" {
		gitlabEnabled = keyMatchesAccount("gitlab.com", conn.User(), keyID)
	}

	log.Printf("%s(%s) connected (%s, %s, gh:%v, gl:%v)",
		conn.RemoteAddr(), keyID, conn.ClientVersion(), conn.User(), githubEnabled, gitlabEnabled)

	// We want to have at least one session opened so we can send messages to it.
	outputReady := false
	outputReadyCh := make(chan void)
	keepalives := make(chan void)
	msgs := make(chan string)
	requested := int32(0)

	defer func() {
		close(msgs)
		s.closeConnection(conn)
	}()

	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				close(keepalives)
				return
			} else {
				keepalives <- v
			}
		}
	}()

	go func() {
		for nc := range newChans {
			newChannel := nc
			go func() {
				if t := newChannel.ChannelType(); t != "session" {
					log.Printf("Rejecting channel type %s", t)
					err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
					if err != nil {
						log.Printf("Failed to reject channel type %s (%s)", t, err)
					}
					return
				}

				channel, sessionReqs, err := newChannel.Accept()
				if err != nil {
					log.Printf("Could not accept channel (%s)", err)
					return
				}

				s.startSession(keyID, conn, channel)
				defer s.endSession(conn, channel)

				if !outputReady {
					outputReadyCh <- v
					outputReady = true
				}

				go func() {
					buf := make([]byte, 256)
					for {
						read, err := channel.Read(buf)
						if err != nil && errors.Is(err, io.EOF) {
							return
						}
						// ctrl-c & ctrl-d
						if bytes.ContainsAny(buf[:read], "\x03\x04") {
							s.endSession(conn, channel)
							break
						}
					}
				}()

				go func() {
					<-time.After(1 * time.Second)
					if atomic.LoadInt32(&requested) == 0 {
						reportStatus(channel, 1)
						_ = channel.Close()
					}
				}()

				for req := range sessionReqs {
					if req.Type == "shell" || req.Type == "pty-req" {
						if err := req.Reply(true, nil); err != nil {
							log.Printf("Could not accept request of type %s (%v)", req.Type, err)
						}
					} else {
						if err := req.Reply(false, nil); err != nil {
							return
						}
					}
				}
			}()
		}
	}()

	go func() {
		<-outputReadyCh

		for msg := range msgs {
			c := s.conns[conn]
			if c != nil {
				for sess := range c.Sessions {
					if _, err := sess.Write([]byte(msg + "\r\n")); err != nil {
						log.Printf("Could not send message %s (%v)", msg, err)
					}
				}
			}
		}
	}()

	for {
		select {
		case req := <-reqs:
			if req == nil {
				return
			}
			switch req.Type {
			case "tcpip-forward":
				var payload remoteForwardRequest
				if err = ssh.Unmarshal(req.Payload, &payload); err != nil {
					log.Printf("Invalid new tcpip-forward request (%v)", err)
					if req.WantReply {
						if err := req.Reply(false, nil); err != nil {
							log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
						}
					}
				} else {
					endpoints := endpointURLs(conn.User(), key, payload.BindPort, githubEnabled, gitlabEnabled)
					atomic.AddInt32(&requested, 1)

					var urls []string
					for _, endpoint := range endpoints {
						urls = append(urls, "https://"+endpoint+"/")
					}
					msgs <- fmt.Sprintf("%d: %s", payload.BindPort, strings.Join(urls, ", "))

					s.Lock()
					for _, endpoint := range endpoints {
						s.insertEndpointTarget(endpoint, &target{
							KeyID:  keyID,
							Remote: conn,
							Host:   payload.BindAddr,
							Port:   payload.BindPort,
						})
					}
					s.Unlock()

					if req.WantReply {
						if err := req.Reply(true, ssh.Marshal(struct{ uint32 }{443})); err != nil {
							log.Printf("Could not accept new channel request of type %s (%v)", req.Type, err)
						}
					}
				}
			case "cancel-tcpip-forward":
				var payload remoteForwardCancelRequest
				if err = ssh.Unmarshal(req.Payload, &payload); err != nil {
					log.Printf("Invalid new tcpip-forward request (%v)", err)
					if req.WantReply {
						if err := req.Reply(false, nil); err != nil {
							log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
						}
					}
				} else {
					endpoints := endpointURLs(conn.User(), key, payload.BindPort, githubEnabled, gitlabEnabled)
					atomic.AddInt32(&requested, 1)

					s.Lock()
					for _, endpoint := range endpoints {
						s.removeEndpointTarget(endpoint, &target{
							KeyID:  keyID,
							Remote: conn,
							Host:   payload.BindAddr,
							Port:   payload.BindPort,
						})
					}
					s.Unlock()

					if req.WantReply {
						if err := req.Reply(true, ssh.Marshal(struct{ uint32 }{443})); err != nil {
							log.Printf("Could not accept new channel request of type %s (%v)", req.Type, err)
						}
					}
				}
			case "keepalive@openssh.com":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					if err := req.Reply(false, nil); err != nil {
						log.Printf("Failed to reply to %v (%v)", req, err)
					} else {
						log.Printf("Rejected request of type %v", req.Type)
					}
				}
			}
		case <-keepalives:
		case <-time.After(10 * time.Second):
			log.Printf("%s(%s) timed out", conn.RemoteAddr(), keyID)
			return
		}
	}
}

func keyMatchesAccount(domain, user, key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/%s.keys", domain, user), nil)
	if err != nil {
		log.Printf("Error creating request to %s for %s (%v)", domain, user, err)
		return false
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	if err != nil {
		log.Printf("Error querying %s for %s (%v)", domain, user, err)
		return false
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error reading response from %s for %s (%v)", domain, user, err)
		return false
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		if strings.TrimRight(parts[1], "=") == key {
			return true
		}
	}
	return false
}

func (s *server) logStats() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		log.Printf("Stats: %d conns, %d endpoints", len(s.conns), len(s.endpoints))
	}
}

func endpointURLs(user string, key *ssh.PublicKey, port uint32, githubEnabled bool, gitlabEnabled bool) []string {
	hasher := sha256.New()
	_, _ = hasher.Write((*key).Marshal())
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strconv.Itoa(int(port))))
	b32 := b32encoder.EncodeToString(hasher.Sum(nil)[:16])
	result := []string{fmt.Sprintf("%s.%s", b32, *domain)}
	if githubEnabled {
		if port == 1 {
			result = append(result, fmt.Sprintf("%s.gh.%s", user, *domain))
		} else {
			result = append(result, fmt.Sprintf("%s--%d.gh.%s", user, port, *domain))
		}
	}
	if gitlabEnabled {
		result = append(result, fmt.Sprintf("%s-%d.gl.%s", user, port, *domain))
	}
	return result
}

func reportStatus(ch ssh.Channel, status byte) {
	_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, status})
}

func addKey(sshConfig *ssh.ServerConfig, path string) {
	privateBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read private key %s (%v)", path, err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key %s (%v)", path, err)
	}

	sshConfig.AddHostKey(private)
}

func main() {
	flag.Parse()

	pool, err := pgxpool.Connect(context.Background(), *pgConn)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	s := newServer(pool)
	go s.logStats()
	go s.serveHTTPS()
	s.serveSSH()
}
