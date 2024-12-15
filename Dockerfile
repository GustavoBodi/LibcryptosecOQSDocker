FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y astyle python3-pytest python3-pytest-xdist unzip \
    xsltproc doxygen graphviz python3-yaml valgrind git cmake ninja-build libssl-dev wget

WORKDIR /app

RUN git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git openssl-oqs && \
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git

WORKDIR /app/liboqs
RUN mkdir build && \
    cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/app/openssl-oqs/oqs .. && \
    ninja && \
    ninja install

WORKDIR /app/openssl-oqs
RUN CFLAGS="-I/app/openssl-oqs/oqs/include -lm" \
    LDFLAGS="-Wl,-rpath,/app/openssl-oqs/oqs/lib -L/app/openssl-oqs/oqs/lib" \
    ./Configure shared linux-x86_64 --prefix=/usr/local/ssl && \
    make -j$(nproc) && \
    make install

ENV LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH
ENV PATH=/usr/local/ssl/bin:$PATH

RUN openssl version -a

WORKDIR /app
COPY libp11-0.4.7.tar.gz .
RUN tar -xvf libp11-0.4.7.tar.gz

WORKDIR /app/libp11-0.4.7
RUN OPENSSL_CFLAGS="-I/usr/ssl/include" \
    OPENSSL_LIBS="-Wl,-rpath -Wl,/usr/ -L/usr/ -lcrypto -ldl" \
    ./configure && \
    make -j$(nproc) && \
    make install

RUN apt-get install -y g++

WORKDIR /app
COPY libcryptosec libcryptosec
WORKDIR /app/libcryptosec
RUN git checkout openssl-1.1.x && \
    export OPENSSL_PREFIX=/usr/local/ssl && \
    export OPENSSL_LIBDIR=/usr/local/ssl/lib && \
    export INSTALL_PREFIX=/usr && \
    export INSTALL_LIBDIR=/usr/lib64 && \
    export LIBP11_PREFIX=/usr/local && \
    export LIBP11_LIBDIR=/usr/local/lib && \
    export LIBP11_INCLUDEDIR=/usr/local/include && \
    make -j$(nproc) && \
    make install

WORKDIR /app

COPY main.cpp .

RUN g++ -Iinclude \
        -I/usr/local/ssl/include/ \
        -I/usr/include/libcryptosec \
        main.cpp \
        -L/usr/local/ssl/lib \
        -L/usr/lib64 \
        -Wl,-rpath,/usr/local/ssl/lib:/usr/lib64 \
        -lcrypto \
        -lcryptosec \
        -Wstack-protector \
        -o cert_gen

RUN chmod +x cert_gen

RUN ./cert_gen
