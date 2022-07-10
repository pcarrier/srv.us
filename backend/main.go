package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	b32encoder = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base64.NoPadding)

	domain          = flag.String("domain", "srv.us", "Domain name under which we run")
	sshPort         = flag.Int("ssh-port", 22, "Port for SSH to bind to")
	httpsPort       = flag.Int("https-port", 443, "Port for SSH to bind to")
	httpsChainPath  = flag.String("https-chain-path", "/etc/letsencrypt/live/srv.us/fullchain.pem", "Path to the certificate chain")
	httpsKeyPath    = flag.String("https-key-path", "/etc/letsencrypt/live/srv.us/privkey.pem", "Path to the private key")
	sshHostKeysPath = flag.String("ssh-host-keys-path", "/etc/ssh", "Path where ssh_host_ecdsa_key, ssh_host_ed25519_key, ssh_host_rsa_key can be found")
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
	conns   map[*ssh.ServerConn]*sshConnection
	tunnels map[string]map[*target]void
}

func newServer() *server {
	return &server{
		conns:   map[*ssh.ServerConn]*sshConnection{},
		tunnels: map[string]map[*target]void{},
	}
}

func (s *server) startSession(keyID string, conn *ssh.ServerConn, ch ssh.Channel) {
	_, _ = ch.Write([]byte("Support: https://discord.gg/6YnHXskF4a\r\n"))

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

	s.Lock()
	defer s.Unlock()

	if s.tunnels[endpoint] != nil {
		s.tunnels[endpoint][t] = v
	} else {
		s.tunnels[endpoint] = map[*target]void{t: v}
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

	if s.tunnels[endpoint] == nil {
		return
	}

	delete(s.tunnels[endpoint], t)
	if len(s.tunnels[endpoint]) == 0 {
		delete(s.tunnels, endpoint)
	}

	sConn := s.conns[t.Remote]
	delete(sConn.TunnelRefs, &tunnelRef{
		Endpoint: endpoint,
		Target:   t,
	})
}

func (s *server) pickTarget(endpoint string) *target {
	s.Lock()
	mapping, found := s.tunnels[endpoint]
	s.Unlock()

	if !found {
		return nil
	} else {
		var candidates []*target
		for c := range mapping {
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
	cert, err := tls.LoadX509KeyPair(*httpsChainPath, *httpsKeyPath)
	if err != nil {
		log.Fatalln(err)
	}

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

		go s.serveHTTPSConnection(conn, &cert)
	}
}

func (s *server) serveHTTPSConnection(raw net.Conn, cert *tls.Certificate) {
	name := ""

	c := &tls.Config{
		Certificates: []tls.Certificate{*cert},
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
		_, _ = https.Write([]byte("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://github.com/pcarrier/srv.us/blob/main/README.md\r\n\r\n"))
		return
	}

	requestedEndpoint := strings.TrimSuffix(name, "."+*domain)

	tgt := s.pickTarget(requestedEndpoint)
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
			log.Printf("%v:%s→%v channel close failed (%d)", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), err)
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
		log.Printf("%v:%s→%v xfer %d", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), b)
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s→%v copy failed (%d)", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), err)
		}
		if err := https.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s→%v close failed (%d)", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), err)
		}
		wg.Done()
	}()

	go func() {
		b, err := io.Copy(sshChannel, https)
		log.Printf("%v:%s←%v xfer %d", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), b)
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s←%v copy failed (%d)", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), err)
		}
		if err := sshChannel.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s←%v close failed (%d)", tgt.Remote.RemoteAddr(), requestedEndpoint, raw.RemoteAddr(), err)
		}
		wg.Done()
	}()

	wg.Wait()
}

func httpErrorOut(w io.Writer, status string, message string) error {
	_, err := w.Write([]byte(fmt.Sprintf("HTTP/1.1 %s\r\nContent-Length: %d\r\n\r\n%s", status, len(message), message)))
	return err
}

func (s *server) serveSSH() {
	sshConfig := ssh.ServerConfig{ServerVersion: "SSH-2.0-" + *domain + "-1.0"}
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
	var key ssh.PublicKey
	config := sshConfig
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		key = k
		return &ssh.Permissions{}, nil
	}

	conn, newChans, reqs, err := ssh.NewServerConn(*tcpConn, config)
	if err != nil {
		return
	}

	keyID := base64.RawStdEncoding.EncodeToString(key.Marshal()[:])
	log.Printf("%s(%s) connected (%s, %s)", conn.RemoteAddr(), keyID, conn.ClientVersion(), conn.User())

	// We want to have at least one session opened so we can send messages to it.
	outputReady := false
	outputReadyCh := make(chan void)
	msgs := make(chan string)
	requested := int32(0)

	defer func() {
		close(msgs)
		s.closeConnection(conn)
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
						return
					}
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
						failWithUsage(channel)
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

	for req := range reqs {
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
				endpoint := endpointURL(key, payload.BindPort)
				atomic.AddInt32(&requested, 1)
				msgs <- fmt.Sprintf("%d: https://%s.%s/", payload.BindPort, endpoint, *domain)

				s.insertEndpointTarget(endpoint, &target{
					KeyID:  keyID,
					Remote: conn,
					Host:   payload.BindAddr,
					Port:   payload.BindPort,
				})

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
				connID := endpointURL(key, payload.BindPort)
				atomic.AddInt32(&requested, 1)
				msgs <- fmt.Sprintf("https://%s.%s/ stops serving %s:%d", connID, *domain, payload.BindAddr, payload.BindPort)

				s.Lock()
				s.removeEndpointTarget(connID, &target{
					KeyID:  keyID,
					Remote: conn,
					Host:   payload.BindAddr,
					Port:   payload.BindPort,
				})
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
	}
}

func (s *server) logStats() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		log.Printf("Stats: %d conns, %d tunnels", len(s.conns), len(s.tunnels))
	}
}

func endpointURL(key ssh.PublicKey, port uint32) string {
	hasher := sha256.New()
	_, _ = hasher.Write(key.Marshal())
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strconv.Itoa(int(port))))
	return b32encoder.EncodeToString(hasher.Sum(nil)[:16])
}

func reportStatus(ch ssh.Channel, status byte) {
	_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, status})
}

func failWithUsage(ch ssh.Channel) {
	_, _ = ch.Write([]byte("Usage: ssh " + *domain + " -R 1:localhost:3000 -R 2:192.168.0.1:80 …\r\n"))
	reportStatus(ch, 1)
	_ = ch.Close()
}

func addKey(sshConfig *ssh.ServerConfig, path string) {
	privateBytes, err := ioutil.ReadFile(path)
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

	s := newServer()
	go s.logStats()
	go s.serveHTTPS()
	s.serveSSH()
}
