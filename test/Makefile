all: ca

user:
	mkdir user/
	ssh-keygen -t ed25519 -f ./user/user_key -C 'root@locahost' -N ""

ca: user
	mkdir ca/
	ssh-keygen -t ed25519 -f ./ca/user_ca_key -C 'User Certificate Authority for Testing' -N ""
	ssh-keygen -s ./ca/user_ca_key -I 'abc' -z '0002' -n root ./user/user_key.pub

docker: ca
	docker build . -t ckrs-ssh-test
	docker run -d -p 2222:22 --name ckrs-ssh-test ckrs-ssh-test

ssh:
	ssh -o CertificateFile=./user/user_key-cert.pub -i ./user/user_key root@localhost -p 2222

clean:
	$(RM) -r user/ ca/
	docker stop ckrs-ssh-test
	docker rm ckrs-ssh-test

.PHONY: clean docker ssh
