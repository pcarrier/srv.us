# launchd launch agent

## Preparation

Create a dedicated, passphraseless SSH key using:

```
ssh-keygen -t ed25519 -N '' -f ~/.ssh/srvus
```

## Installation

- Tweak `us.srv.plist` to your needs:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>us.srv</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>exec ssh srv.us -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -o ServerAliveInterval=5 -i ~/.ssh/srvus -T -R 1:localhost:3000 -R 2:192.168.0.1:80</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/srv.us.log</string>
    <key>StandardOutPath</key>
    <string>/tmp/srv.us.log</string>
</dict>
</plist>
```

- Place it in `~/Library/LaunchAgents`, then run:

```
$ launchctl load -w ~/Library/LaunchAgents/us.srv.plist
```

- Observe the output with:

```
$ tail -f /tmp/srv.us.log
```

## Making changes

After modifying `us.srv.plist`, run:

```
$ launchctl unload ~/Library/LaunchAgents/us.srv.plist && launchctl load -w ~/Library/LaunchAgents/us.srv.plist
```

## Starting & stopping

```
$ launchctl start us.srv
$ launchctl stop us.srv
```
