## Libcryptosec com OpenSSL 1.1.1 OQS

Esta é uma demonstração do uso da libcryptosec com o OpenSSL 1.1.1 OQS para a
emissão de certificados pós-quânticos.

### Como Usar
Para fazer uso é muito simples, basta rodar o Makefile que baixará a libp11 que
logo depois rodará a Dockerfile e emitirá um certificado auto-assinado.

```bash
make
```

Logo depois disso, deve haver uma arquivo certificado.crt na pasta em que está
esse repositório.
