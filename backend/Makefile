srvus: main.go
	GOOS=linux GOARCH=amd64 go build -o srvus .
.PHONY: deploy run
privkey.pem:
	openssl ecparam -genkey -name prime256v1 -out privkey.pem
csr.pem: privkey.pem
	openssl req -new -out csr.pem -key privkey.pem -config openssl.cnf
fullchain.pem: privkey.pem csr.pem
	openssl x509 -req -days 10000 -in csr.pem -signkey privkey.pem -out fullchain.pem
deploy: srvus
	rsync -aP srvus srvus: && ssh srvus 'doas bash -c "install srvus /usr/local/bin/srvus; systemctl restart srvus"'
run: main.go fullchain.pem privkey.pem
	sudo mkdir -p /etc/letsencrypt/live/srv.us
	sudo cp fullchain.pem privkey.pem /etc/letsencrypt/live/srv.us
	sudo go run .
