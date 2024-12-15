#include <libcryptosec/certificate/CertificateBuilder.h>
#include <openssl/evp.h>

int main () {
    // O EVP_PKEY e EVP_PKEY_CTX precisam ser inicializados e o CTX em específico com o algoritmo pós-quantum desejado
    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM2, NULL);

    if (key == NULL) {
        std::cout << "key_new failed" << std::endl;
        std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return 1;
    }

    if (ctx == NULL) {
        std::cout << "ctx_new failed" << std::endl;
        std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return 1;
    }

    // Inicializamos o Keygen com o CTX do algoritmo pós-quantum desejado
    if (!EVP_PKEY_keygen_init(ctx)) {
        std::cout << "init failed" << std::endl;
        std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return 1;
    }

    // Geramos a chave com o CTX do algoritmo pós-quantum desejado e a chave é carregada em key
    if (!EVP_PKEY_keygen(ctx, &key))
    {
        std::cout << "keygen failed" << std::endl;
        std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return 1;
    }

    // A partir do EVP_PKEY contendo a chave, utilizamos ele pra construir um PublicKey e PrivateKey
    // Obs: é possível que o programa dê throw na criação, isso ocorre porque o método AsymmetricKey::getAlgorithm()
    //      não possui suporte as chaves pós-quantum e isso ainda precisa ser implementado. Uma solução temporária
    //      é simplesmente comentar a chamada desse método no construtor de AsymmetricKey.
    PublicKey pub(key);
    PrivateKey priv(key);

    // Daqui para baixo é uso padrão da Libcryptosec
    CertificateBuilder builder;
    RDNSequence rdn;

    rdn.addEntry(RDNSequence::COUNTRY, "BR");
    rdn.addEntry(RDNSequence::STATE_OR_PROVINCE, "SC");
    rdn.addEntry(RDNSequence::LOCALITY, "Florianopolis");
    rdn.addEntry(RDNSequence::ORGANIZATION, "UFSC");
    rdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "LabSEC");
    rdn.addEntry(RDNSequence::COMMON_NAME, "OpenSSL Dilithium2");

    builder.setSubject(rdn);
    builder.setIssuer(rdn);
    builder.setPublicKey(pub);

    Certificate *certificate = builder.sign(priv, MessageDigest::SHA256);
    std::cout << certificate->getPemEncoded() << std::endl;

    if (certificate->verify(pub)) {
        std::cout << "verified" << std::endl;
    }

    X509* cert_x509 = certificate->getX509();

    FILE *fp = fopen("certificado.crt", "w");

    if (fp == NULL) {
        std::cout << "Erro na abertura do arquivo" << std::endl;
        return 1;
    }

    if (PEM_write_X509(fp, cert_x509) != 1) {
        std::cout << "Erro na escrita do arquivo" << std::endl;
    }

    fclose(fp);

    return 0;
}
