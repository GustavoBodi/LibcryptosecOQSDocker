all: libp11-0.4.7.tar.gz
	docker build -t openssl . && \
	container_openssl=$$(docker create openssl) && \
	docker cp $$container_openssl:/app/certificado.crt . && \
	docker rm $$container_openssl

libp11-0.4.7.tar.gz:
	wget https://github.com/OpenSC/libp11/releases/download/libp11-0.4.7/libp11-0.4.7.tar.gz
