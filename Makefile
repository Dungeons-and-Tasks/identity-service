PWD = $(shell pwd)
CONFIG = $(PWD)/config
ENV = dev

create-keypair:
	@echo "Creating an rsa 256 key pair"
	openssl genpkey -algorithm RSA -out $(CONFIG)/rsa_private_$(ENV).pem -pkeyopt rsa_keygen_bits:2048
	openssl rsa -in $(CONFIG)/rsa_private_$(ENV).pem -pubout -out $(CONFIG)/rsa_public_$(ENV).pem

init:
	go run cmd/init/init.go

dev:
	go run cmd/main.go