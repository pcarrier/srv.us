<p align="center">
  <img src="https://raw.githubusercontent.com/pcarrier/srv.us/main/assets/icon.webp" width="128" height="128" alt="Logo"/>
</p>

<h1 align="center"><tt>ssh srv.us</tt>:<br/>expose local HTTP services online</h1>

Yet another solution to **expose any HTTP server to the Internet through a tunnel**.

**Free & open source. Stable URLs. No accounts. Nothing to install outside [Windows](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse). Your data is your data.**

Got a server running on port 3000? Run `ssh srv.us -R 1:localhost:3000` and it'll respond with its public HTTPS URL(s), available until you close `ssh` with Ctrl-c or Ctrl-d, or get disconnected (see [Staying up](#staying-up)).

It fails with `Permission denied (publickey).`? You need an SSH key; use `ssh-keygen -t ed25519`. Another problem? [Contact support](https://discord.gg/6YnHXskF4a).

## Demo

Set up 2 tunnels, the first to `localhost` port `3000` and the second to `192.168.0.1` port `80`:

```
$ ssh srv.us -R 1:localhost:3000 -R 2:192.168.0.1:80
Support: https://discord.gg/6YnHXskF4a
1: https://qp556ma755ktlag5b2xyt334ae.srv.us/, https://pcarrier.gh.srv.us/
2: https://z2tdoto6u3mddntra45qkm45ci.srv.us/, https://pcarrier--2.gh.srv.us/
```

Test the first tunnel with a single-request server:

```
$ printf 'HTTP/1.1 200 OK\r\n\r\nHello through srv.us!\n' | nc -l 3000 > /dev/null &
$ curl https://qp556ma755ktlag5b2xyt334ae.srv.us/
Hello through srv.us!
```

## Notes

If you forget the syntax, `ssh srv.us` prints an example.

URLs are stable for a given SSH key and number (1 and 2 in examples), with no risk of collision, the assigned subdomain being the first 16 bytes of their SHA-256 in base32.

### Staying up

`ssh` will terminate when the connection is lost or the service restarted.
- To reconnect automatically in your shell, use `until ssh srv.us -R 1:localhost:3000; do echo Restarting…; done`.
- To use as a service on Linux that reconnects automatically, see [systemd-example](systemd-example/).

### Load balancing

When there are multiple tunnels for a URL, client connections are spread between them randomly. We do not perform any health checks.

### GitHub & GitLab subdomains

Your SSH username is looked up on GitHub and GitLab; if the corresponding account authorizes your SSH key,
we expose your services over named URLs.

For example, for `pcarrier` on GitHub, service number 1 is also exposed as https://pcarrier.gh.srv.us/
and service number 2 as https://pcarrier--2.gh.srv.us/.

- If your local username does not match your GitHub/GitLab login, use `ssh your-git-login@srv.us …`.
- Conversely, if they do match but you do not want to use this feature, use `ssh nomatch@srv.us …`.

### Privacy

We do not record or inspect your traffic, or even parse headers (as such, non-HTTP protocols work too).

However, we log IPs & ports, SSH usernames & keys, connections, tunnels, and byte counts for up to 1 day.

Those logs never leave the server, and are only ever used for operational purposes and to troubleshoot reported issues.

We reserve the right to access your endpoint in the handling of abuse reports.

### That's it?

Like any tunnel, the bandwidth of your service is consumed twice. If [sponsorships](https://github.com/sponsors/pcarrier) don't cover operating costs and they increase significantly, heavy usage may require financial contribution to avoid throttling.

There are [a lot of alternatives](https://github.com/anderspitman/awesome-tunneling). As with [ident.me](https://api.ident.me), I hope you enjoy this simple take on a common problem. ❤️

That's it.
