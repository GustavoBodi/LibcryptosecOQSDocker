all: libp11-0.4.7.tar.gz output docker_build
	container_openssl=$$(docker create openssl) && \
	docker cp $$container_openssl:/app/certificado.crt ./output && \
	docker rm $$container_openssl

docker_build:
	docker build -t openssl .

libp11-0.4.7.tar.gz:
	wget https://github.com/OpenSC/libp11/releases/download/libp11-0.4.7/libp11-0.4.7.tar.gz

output:
	mkdir output

clean:
	rm -rf output
	rm libp11-0.4.7.tar.gz

.PHONY: docker_build clean
