## Libcryptosec com OpenSSL 1.1.1 OQS

Esta é uma demonstração do uso da libcryptosec com o OpenSSL 1.1.1 OQS para a
emissão de certificados pós-quânticos.

### Como Usar
Para fazer uso é muito simples, basta rodar o Makefile que baixará a libp11,
rodará o Dockerfile e emitirá um certificado auto-assinado.

```bash
make
```

Logo depois disso haverá um arquivo certificado.crt na pasta output.
