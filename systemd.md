# systemd service

*(Replace `sudo` with `doas` if that's what your system uses.)*

## Preparation

Create a user with its passphraseless SSH key using:

```
$ sudo useradd -m srvus && sudo -u srvus ssh-keygen -t ed25519 -N '' -f /home/srvus/.ssh/id_ed25519
```

## Installation

- Tweak `srvus.service` to your needs:

```
[Service]
ExecStart=ssh srv.us -o StrictHostKeyChecking=accept-new -T -R 1:localhost:3000 -R 2:192.168.0.1:80
User=srvus
Restart=on-failure
RestartSec=1s

[Unit]
After=network.target

[Install]
WantedBy=multi-user.target
```

- Place it in `/etc/systemd/system`, then run:

```
$ sudo systemctl enable --now srvus
```

## Troubleshooting

Read logs with:

```
$ sudo journalctl -fun 100 srvus
```

## Making changes

After modifying `srvus.service`, run:

```
# systemctl daemon-reload && systemctl restart srvus
```

## Starting & stopping

```
$ sudo systemctl start srvus
$ sudo systemctl stop srvus
```
