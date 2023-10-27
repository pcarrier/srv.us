# non-http protocol
Let's have a look at how to expose your server's ssh port and how to access it from a client through [stunnel](https://www.stunnel.org/).

## On the server
```
$ ssh srv.us -R 1:localhost:22
1: https://qp556ma755ktlag5b2xyt334ae.srv.us/, https://pcarrier.gh.srv.us/
```

## On the client
### Sample config
```
[ssh]
client = yes
accept = 127.0.0.1:2022
connect = qp556ma755ktlag5b2xyt334ae.srv.us:443
```
### Windows
1. Download and install stunnel from [here](https://www.stunnel.org/downloads/stunnel-latest-win64-installer.exe)
2. Open Start Menu → stunnel CurrentUser → Edit stunnel.conf
3. Add the sample config to the config file then save
4. Start stunnel from Start Menu → stunnel CurrentUser → stunnel GUI Start
5. Connecting to the server
```
ssh 127.0.0.1 -p 2022
```
### Debian/Ubuntu
1. Install stunnel
```
sudo apt -yq install stunnel4
```
2. Put the sample config in `/etc/stunnel/stunnel.conf`
3. Start stunnel
```
sudo service stunnel4 start
```
Or
```
sudo systemctl start stunnel4
```
4. Connecting to the server
  ```
  ssh 127.0.0.1 -p 2022
  ```
### Android
1. Install [SSLSocks](https://play.google.com/store/apps/details?id=link.infra.sslsocks)
2. Open the apps and put the sample config in the `CONFIG` tab
3. Tap on `HOME` tab and tap on `Not running` to change it to `Running`
4. Connecting to the server (from termux or any other terminal emulator that support ssh client)
  ```
  ssh 127.0.0.1 -p 2022
  ```
