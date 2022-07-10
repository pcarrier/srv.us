.PHONY: deploy run tunnel

srvus: main.go
	GOOS=linux GOARCH=amd64 go build -o srvus .

privkey.pem:
	openssl ecparam -genkey -name prime256v1 -out privkey.pem

csr.pem: privkey.pem
	openssl req -new -out csr.pem -key privkey.pem -config openssl.cnf

fullchain.pem: privkey.pem csr.pem
	openssl x509 -req -days 10000 -in csr.pem -signkey privkey.pem -out fullchain.pem

ssh_host_rsa_key:
	ssh-keygen -q -N '' -t rsa -b 4096 -f ssh_host_rsa_key

ssh_host_ecdsa_key:
	ssh-keygen -q -N '' -t ecdsa -f ssh_host_ecdsa_key

ssh_host_ed25519_key:
	ssh-keygen -q -N '' -t ed25519 -f ssh_host_ed25519_key

deploy: srvus
	rsync -aP srvus srvus: && ssh srvus 'doas bash -c "install srvus /usr/local/bin/srvus; systemctl restart srvus"'

run: main.go fullchain.pem privkey.pem ssh_host_rsa_key ssh_host_ecdsa_key ssh_host_ed25519_key
	go run . -domain srvtest -https-chain-path fullchain.pem -https-key-path privkey.pem -ssh-host-keys-path . -https-port 4443 -ssh-port 2222

tunnel:
	ssh localhost -o StrictHostKeyChecking=accept-new -p 2222 -R 1:localhost:3000
