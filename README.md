<p align="center">
  <img src="assets/icon.webp" width="128" height="128" alt="Logo"/>
</p>

<h1 align="center"><tt>ssh srv.us</tt>:<br/>expose local services over TLS online<br/>(and a pastebin)</h1>

* [Exposing services](#exposing-services)
* [Sharing files](#sharing-files)
* [`echo`](#echo)
* [Finding my IP](#finding-my-ip)

## Exposing services

Yet another solution to **expose any HTTP server to the Internet through a tunnel**. In many situations, [tailscale](https://tailscale.com/) or forwarding ports on your NAT box and [Let's Encrypt](https://letsencrypt.org/) are better options.

**Free & [fully open source](https://github.com/pcarrier/srv.us). Stable URLs derived from your SSH key. No accounts. Nothing to install outside [Windows](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).**

Got a server running on port 3000? Run `ssh srv.us -R 1:localhost:3000` and it'll respond with its public HTTPS URL(s), available until you close `ssh` with Ctrl-c or Ctrl-d, or get disconnected (see [Staying up](#staying-up)).

It fails with `Permission denied (publickey).`? You need an SSH key; use `ssh-keygen -t ed25519` (defaults work). Another problem? [Contact support](https://discord.gg/6YnHXskF4a).

If you forget the syntax, `ssh srv.us` prints an example.

### Demo

Set up 2 tunnels, the first to `localhost` port `3000` and the second to `192.168.0.1` port `80`:

```
$ ssh srv.us -R 1:localhost:3000 -R 2:192.168.0.1:80
1: https://qp556ma755ktlag5b2xyt334ae.srv.us/, https://pcarrier.gh.srv.us/
2: https://z2tdoto6u3mddntra45qkm45ci.srv.us/, https://pcarrier--2.gh.srv.us/
```

Test the first tunnel with a single-request server:

```
$ printf 'HTTP/1.1 200 OK\r\n\r\nHello through srv.us!\n' | nc -l 3000 > /dev/null &
$ curl https://qp556ma755ktlag5b2xyt334ae.srv.us/
Hello through srv.us!
```

### GitHub & GitLab subdomains

If either GitHub or GitLab authorizes your SSH key for your login, we also expose your tunnels over correspondingly named URLs.

For example, for login `jdoe`:
- On GitHub, tunnel 1 is also [jdoe.gh.srv.us](https://jdoe.gh.srv.us/), tunnel 2 [jdoe--2.gh.srv.us](https://jdoe--2.gh.srv.us/);
- On GitLab, tunnel 1 is also [jdoe-1.gl.srv.us](https://jdoe-1.gl.srv.us/), tunnel 2 [jdoe-2.gl.srv.us](https://jdoe-2.gl.srv.us/).

*(The discrepancy is due to insufficient constraints on GitLab usernames.
We need to prevent collisions between users `jdoe` and eg `jdoe--2`,
whereas GitHub does not allow repeating `-` in usernames.)*

Note that this feature is optional and might not work out of the box:
- If your local username does not match your GitHub/GitLab login, use `ssh your-git-login@srv.us …`;
- Conversely, if they do match but you do not want to use this feature, use `ssh nomatch@srv.us …`.

### Staying up

`ssh` eventually terminates when the connection is lost or the service restarted.
- To reconnect automatically in your shell, use `until ssh srv.us -R 1:localhost:3000; do echo Restarting…; done`.
- To use as a service on Linux that reconnects automatically, see [systemd service](systemd.md).
- To use as a launch agent on MacOS that reconnects automatically, see [launchd launch agent](launchd.md).

### Load balancing

When there are multiple tunnels for a URL, client connections are spread between them randomly. We do not perform any health checks.

### Privacy

We do not record any of your traffic.

However, we log IPs & ports, SSH usernames & keys, connections, tunnels, and byte counts for up to 1 day.

Those logs never leave the server, and are only ever used for operational purposes and to troubleshoot reported issues.

We reserve the right to access your endpoint in the handling of abuse reports.

### Implementation

The [Go backend](https://github.com/pcarrier/srv.us/tree/main/backend) runs on as a systemd service on a single instance and uses certificates provisioned by [Let's Encrypt](https://letsencrypt) using a systemd timer with a corresponding service where `ExecStart=/snap/bin/certbot renew --agree-tos --manual --preferred-challenges=dns --post-hook /usr/local/bin/certbot-renewed --manual-auth-hook /usr/local/bin/certbot-auth` (`certbot-renewed` restarts the backend and `certbot-auth` integrates with CloudFlare's DNS API). I have [plans to scale](https://github.com/pcarrier/srv.us/issues/8) when it becomes necessary.

### That's it?

Non-HTTP protocols work too, as we only rely on the protocol to report errors. See [non-http protocols](non-http.md).

The bandwidth used for your traffic is consumed twice. If [sponsorships](https://github.com/sponsors/pcarrier) don't cover operating costs and they increase significantly, heavy usage may require financial contribution to avoid throttling.

There are [a lot of alternatives](https://github.com/anderspitman/awesome-tunneling). I hope you enjoy this simple take on a common problem. ❤️

That's it.

## Sharing files

Simple pastebin feature. POST your content and get a URL back, followed by a newline. For example:

```
$ doas dmesg | curl --data-binary @- https://srv.us
https://srv.us/e3jyi7vowlwqyzaewdfv444laadkys4a
$
```

## `echo`

Returns what you submit.

```
$ curl -D- --json $(jo a=42) https://srv.us/echo
HTTP/1.1 200 OK
Content-Type: application/json

{"a":42}
```

## Finding my IP

Please take a look at [ident.me](https://api.ident.me).
