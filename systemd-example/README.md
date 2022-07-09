# systemd automation

*(Replace `sudo` with `doas` if that's what your system uses.)*

## Preparation

```
# sudo useradd -m srvus && sudo -u srvus ssh-keygen -t ed25519 -N '' -f /home/srvus/.ssh/id_ed25519
```

## Installation

Tweak `srvus.service` to your needs, place it in `/etc/systemd/system`, then run:

```
# systemctl enable --now srvus
```
