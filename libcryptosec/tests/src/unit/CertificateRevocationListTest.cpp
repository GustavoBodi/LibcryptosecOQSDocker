#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>

#include <sstream>
#include <gtest/gtest.h>

/**
 * @brief Testes unitários da classe CertificateRevocationList
 */
class CertificateRevocationListTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        crl = new CertificateRevocationList(crlPem);
    }

    virtual void TearDown() {
        free(crl);
    }

    /**
     * @brief Generates the expected value from getXmlEncoded
     * @param tab string to insert tab in XML value
     */
    std::string genXml(std::string tab = "")
    {
        std::string ret = "";

        ret += tab + "<certificateRevocationList>" + "\n";
        ret += tab + "\t" + "<tbsCertList>" + "\n";
        ret += tab + "\t\t" + "<version>" + std::to_string(version) + "</version>" + "\n";
        ret += tab + "\t\t" + "<serialNumber>" + std::to_string(serial) + "</serialNumber>" + "\n";
       
        ret += tab + "\t\t" + "<issuer>" + "\n";
        ret += tab + "\t\t\t" + "<RDNSequence>" + "\n";
        ret += tab + "\t\t\t\t" + "<countryName>" + rdnIssuerCountry + "</countryName>" + "\n";
        ret += tab + "\t\t\t\t" + "<stateOrProvinceName>" + rdnIssuerState + "</stateOrProvinceName>" + "\n";
        ret += tab + "\t\t\t\t" + "<localityName>" + rdnIssuerLocality + "</localityName>" + "\n";
        ret += tab + "\t\t\t\t" + "<organizationName>" + rdnIssuerOrganization + "</organizationName>" + "\n";
        ret += tab + "\t\t\t\t" + "<commonName>" + rdnIssuerCommonName + "</commonName>" + "\n";
        ret += tab + "\t\t\t" + "</RDNSequence>" + "\n";
        ret += tab + "\t\t" + "</issuer>" + "\n";
        
        ret += tab + "\t\t" + "<lastUpdate>" + stampLast + "</lastUpdate>" + "\n";
        ret += tab + "\t\t" + "<nextUpdate>" + stampNext + "</nextUpdate>" + "\n";
        
        ret += tab + "\t\t" + "<revokedCertificates>" + "\n";
        ret += tab + "\t\t\t" + "<revokedCertificate>" + "\n";
        ret += tab + "\t\t\t\t" + "<certificateSerialNumber>" + revSerialOneDec + "</certificateSerialNumber>" + "\n";
        ret += tab + "\t\t\t\t" + "<revocationDate>" + revStampOne + "</revocationDate>" + "\n";
        ret += tab + "\t\t\t\t" + "<reason>" + "keyCompromise" + "</reason>" + "\n";
        ret += tab + "\t\t\t" + "</revokedCertificate>" + "\n";

        ret += tab + "\t\t\t" + "<revokedCertificate>" + "\n";
        ret += tab + "\t\t\t\t" + "<certificateSerialNumber>" + revSerialTwoDec + "</certificateSerialNumber>" + "\n";
        ret += tab + "\t\t\t\t" + "<revocationDate>" + revStampTwo + "</revocationDate>" + "\n";
        ret += tab + "\t\t\t\t" + "<reason>" + "caCompromise" + "</reason>" + "\n";
        ret += tab + "\t\t\t" + "</revokedCertificate>" + "\n";

        ret += tab + "\t\t" + "</revokedCertificates>" + "\n";
        ret += tab + "\t" + "</tbsCertList>" + "\n";

        ret += tab + "\t" + "<signatureAlgorithm>" + "\n";
        ret += tab + "\t\t" + "<algorithm>" + "sha512WithRSAEncryption" + "</algorithm>" + "\n";
        ret += tab + "\t" + "</signatureAlgorithm>" + "\n";

        ret += tab + "\t" + "<signatureValue>" + crlSignatureValue + "</signatureValue>" + "\n";

        ret += tab + "</certificateRevocationList>" + "\n";

        return ret;
    }

    /**
     * @brief Tests getting the Serial Number (CRL Number) of the CRL
     */
    void testSerialNumber()
    {
        ASSERT_EQ(crl->getSerialNumber(), serial);
    }

    /**
     * @brief Tests getting the Serial Number (CRL Number) of the CRL in BigInt
     */
    void testSerialNumberBigInt()
    {
        BigInteger bi;

        bi = crl->getSerialNumberBigInt();
        ASSERT_EQ(bi, serialBigInt);
    }

    /**
     * @brief Tests getting the Serial Number (CRL Number) of the base CRL
     */
    void testBaseCRLNumber()
    {
        ASSERT_EQ(crl->getBaseCRLNumber(), baseCrl);
    }

    /**
     * @brief Tests getting the Serial Number (CRL Number) of the base CRL in BigInt
     */
    void testBaseCRLNumberBigInt()
    {
        BigInteger bi;

        bi = crl->getBaseCRLNumberBigInt();
        ASSERT_EQ(bi.toDec(), baseCrlString);
    }

    /**
     * @brief Tests getting the version of the CRL
     */
    void testVersion()
    {
        ASSERT_EQ(crl->getVersion(), version);
    }

    /**
     * @brief Tests getting the Issuer of the CRL
     */
    void testIssuer()
    {
        RDNSequence rdn;
        rdn = crl->getIssuer();

        ASSERT_EQ(rdn.getEntries(RDNSequence::COUNTRY)[0], rdnIssuerCountry);
        ASSERT_EQ(rdn.getEntries(RDNSequence::STATE_OR_PROVINCE)[0], rdnIssuerState);
        ASSERT_EQ(rdn.getEntries(RDNSequence::LOCALITY)[0], rdnIssuerLocality);
        ASSERT_EQ(rdn.getEntries(RDNSequence::ORGANIZATION)[0], rdnIssuerOrganization);
        ASSERT_EQ(rdn.getEntries(RDNSequence::COMMON_NAME)[0], rdnIssuerCommonName);
    }

    /**
     * @brief Tests getting the LastUpdate DateTime of the CRL
     */
    void testLastUpdate()
    {
        DateTime dt;
        dt = crl->getLastUpdate();

        ASSERT_EQ(dt.getDateTime(), epochLast);
    }

    /**
     * @brief Tests getting the NextUpdate DateTime of the CRL
     */
    void testNextUpdate()
    {
        DateTime dt;
        dt = crl->getNextUpdate();

        ASSERT_EQ(dt.getDateTime(), epochNext);
    }

    /**
     * @brief Tests getting a list of the RevokedCertificates of the CRL
     */
    void testRevokedCertificate()
    {
        std::vector<RevokedCertificate> revoked;
        revoked = crl->getRevokedCertificate();

        ASSERT_EQ(revoked.size(), 2);

        BigInteger bi;
        DateTime dt;
        RevokedCertificate rev;

        rev = revoked[1];
        bi = rev.getCertificateSerialNumberBigInt();
        dt = rev.getRevocationDate();
        ASSERT_EQ(bi.toHex(), revSerialTwo);
        ASSERT_EQ(dt.getDateTime(), revEpochTwo);
        ASSERT_EQ(rev.getReasonCode(), revReasonTwo);

        rev = revoked[0];
        bi = rev.getCertificateSerialNumberBigInt();
        dt = rev.getRevocationDate();
        ASSERT_EQ(bi.toHex(), revSerialOne);
        ASSERT_EQ(dt.getDateTime(), revEpochOne);
        ASSERT_EQ(rev.getReasonCode(), revReasonOne);
    }

    /**
     * @brief Tests getting the CRLNumberExtension and check its values
     */
    void testExtensionCrlNumber() {
        std::vector<Extension *> exts;
        CRLNumberExtension ext;

        exts = crl->getExtension(Extension::CRL_NUMBER);
        ASSERT_EQ(exts.size(), 1);

        ext = CRLNumberExtension(exts[0]->getX509Extension());
        ASSERT_EQ(ext.getSerial(), serial);
    }

    /**
     * @brief Tests getting the DeltaCRLIndicatorExtension and check its values
     */
    void testExtensionDeltaCrlIndicator()
    {
        std::vector<Extension *> exts;
        DeltaCRLIndicatorExtension ext;

        exts = crl->getExtension(Extension::DELTA_CRL_INDICATOR);
        ASSERT_EQ(exts.size(), 1);
        
        ext = DeltaCRLIndicatorExtension(exts[0]->getX509Extension());
        ASSERT_EQ(ext.getSerial(), baseCrl);
    }

    /**
     * @brief Tests getting the AuthorityKeyIdentifierExtension and check its values
     */
    void testExtensionAuthorityKeyIdentifier()
    {
        std::vector<Extension *> exts;
        AuthorityKeyIdentifierExtension ext;

        exts = crl->getExtension(Extension::AUTHORITY_KEY_IDENTIFIER);
        ASSERT_EQ(exts.size(), 1);

        ext = AuthorityKeyIdentifierExtension(exts[0]->getX509Extension());
        ASSERT_EQ(ext.getKeyIdentifier().toHex(), crlPublicKey.getKeyIdentifier().toHex());
    }

    /**
     * @brief Tests getting a vector with all of the CRL's Extensions
     */
    void testExtensions()
    {
        std::vector<Extension *> exts;

        exts = crl->getExtensions();

        ASSERT_EQ(exts.size(), 3);
    }

    /**
     * @brief Tests verifying the signature of the CRL
     */
    void testVerifySignature()
    {
        ASSERT_TRUE(crl->verify(crlPublicKey));
    }

    /**
     * @brief Tests obtaining the XML Encoded value of the CRL
     */
    void testXmlEncoded()
    {
        std::string xml = genXml();

        ASSERT_EQ(crl->getXmlEncoded(), xml);
    }

    /**
     * @brief Tests obtaining the XML Encoded value of the CRL when inserting a tab
     */
    void testXmlEncodedTab()
    {
        std::string tab = "tab";
        std::string xml = genXml(tab);

        ASSERT_EQ(crl->getXmlEncoded(tab), xml);
    }

    /**
     * @brief Tests verifying signature with the wrong PublicKey
     */
    void testVerifySignatureWrongPublicKey()
    {
        ASSERT_FALSE(crl->verify(crlWrongPublicKey));
    }

    /**
     * @brief Tests PEM Encoded constructor of a CRL when using an invalid PEM value
     */
    void testInvalidPem()
    {
        ASSERT_THROW(CertificateRevocationList invalid(crlInvalidPem), EncodeException);
    }

    /**
     * @brief Tests DER Encoded constructor of a CRL when using an invalid DER value
     */
    void testInvalidDER()
    {
        ByteArray invalidDER(crlInvalidPem); //it can be anything, really

        ASSERT_THROW(CertificateRevocationList invalid(invalidDER), EncodeException);
    }

    /**
     * @brief Tests X509_CRL constructor of a CRL when using a null pointer
     */
    void testInvalidCRL()
    {
        X509_CRL *crl = NULL;
        CertificateRevocationList invalid(crl);

        ASSERT_THROW(invalid.getPemEncoded(), EncodeException);
    }

    CertificateRevocationList *crl;

    static std::string crlPem;
    static std::string crlPrivateKeyPem;
    static std::string crlPublicKeyPem;
    static std::string crlWrongPublicKeyPem;
    static std::string crlSignatureValue;

    static std::string crlInvalidPem;

    static PrivateKey crlPrivateKey;
    static PublicKey crlPublicKey;
    static PublicKey crlWrongPublicKey;

    static MessageDigest::Algorithm mdAlgorithm;
    static int serial;
    static BigInteger serialBigInt;
    static int version;

    static std::string rdnIssuerCountry;
    static std::string rdnIssuerState;
    static std::string rdnIssuerLocality;
    static std::string rdnIssuerOrganization;
    static std::string rdnIssuerCommonName;

    static int epochLast;
    static std::string stampLast;
    static int epochNext;
    static std::string stampNext;

    static std::string revSerialOne;
    static std::string revSerialOneDec;
    static int revEpochOne;
    static std::string revStampOne;
    static RevokedCertificate::ReasonCode revReasonOne;

    static std::string revSerialTwo;
    static std::string revSerialTwoDec;
    static int revEpochTwo;
    static std::string revStampTwo;
    static RevokedCertificate::ReasonCode revReasonTwo;


    static long baseCrl;
    static std::string baseCrlString;
};

/*
 * Initialization of variables used in the tests
 */
std::string CertificateRevocationListTest::crlPem = "-----BEGIN X509 CRL-----" "\n"
"MIICSDCCATACAQEwDQYJKoZIhvcNAQENBQAwbDELMAkGA1UEBhMCQlIxEjAQBgNV" "\n"
"BAgMCVNhbyBQYXVsbzESMBAGA1UEBwwJU2FvIFBhdWxvMRQwEgYDVQQKDAtDZXJ0" "\n"
"IFNpZ25lcjEfMB0GA1UEAwwWUm9uYWxkbyBDZXJ0IFNpZ25lciBWMxcNMTcwMjIz" "\n"
"MjI0NTA3WhcNMjIxMDA2MjI0NTA3WjBTMCgCCQCaMpivtaxxxxcNMTcwMjIzMjI0" "\n"
"NTE4WjAMMAoGA1UdFQQDCgEBMCcCCB7W61ZXiOOOFw0xNzAyMjUwMjMxNDdaMAww" "\n"
"CgYDVR0VBAMKAQKgOzA5MAoGA1UdFAQDAgEUMAoGA1UdGwQDAgETMB8GA1UdIwQY" "\n"
"MBaAFHLn9A7bmtn7rZAw+mnqinFVUq4/MA0GCSqGSIb3DQEBDQUAA4IBAQCJAyeY" "\n"
"0sjQoEovkvKYXtUXXfsYtD39yHbJWmuFaLbxxODyNHnvFjfFAhJagHXitqohyH4W" "\n"
"sYtefxx1UMk1KGjpChUKYtBExoXYG4XcNobXfOAdW5GaFVGwAELe/EPf20tR3q0O" "\n"
"tUBUHW8+K7w0koO/EAlJyDoJ+O+DF96o7LE/XCAyrlNITAR3ebQS6PNxu8z/HakS" "\n"
"Z75WFcpFguHc/cCX6jv/DtX9LFfsRk4sEoZic2G0vfmRg1Hp3m91zSLktkWCK2tM" "\n"
"mwQAOySYNq9z1pXzoXbbhQJvblpXerG6o5DTTOohWtOq/596aLqKalgQF8SVPVw5" "\n"
"F8lXjNm0euhjPQM9" "\n"
"-----END X509 CRL-----" "\n";

std::string CertificateRevocationListTest::crlPrivateKeyPem = "-----BEGIN PRIVATE KEY-----" "\n"
"MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC8IJ82n1/0wPCg" "\n"
"lr+31MxdxiNcYULGkCqEADNHxtIhLND+ol2QSqakg3VsQhZBkanN4henhl2yWlnY" "\n"
"ownc5clZ2LucQ6D4Xgpx6v6pHNVuOoahnkFNGijwb8aY/+PxHv769mFVQFJsNlZg" "\n"
"DuzK0R6fwcZ6JFRcYMYm7Y4sB2+BuyAMmvYN0MI1Q/9DxRP6B56KRok0U/tCO/Eo" "\n"
"nb2oqhGlQfPLTb60mYeTnHE8c/xM13Raq53UShrtAa0RHEuSRKI+5JhkehrA3Oi9" "\n"
"lFvvhxNOAuzqzAISADtyWq5eEYyd9WE7/2jYB7NWQuvfHuEkwFKDPhKg9FkqzUXv" "\n"
"occP/ISzAgMBAAECggEBALbIT0joAngwOdsdfLqks8dsqpCoIxP/oH9OHoTfhOwc" "\n"
"uhadNKDsFwsCesUrVKpyV3Qk9uyanVCbfm4AwqVwUXjNHkNOZgjKfgV+190BmdEW" "\n"
"ZhaDR1kdUKeDQocHILX2crDtT1ZgP3TKOpPsDF9mXQXFZQzpXVm/4OaTqq3Wr51v" "\n"
"we6ScsSUnM5cHpcSfH6IoW/WFQds2d9tpBiGbEi9zCrbE9EYMKImo922n/WGXurN" "\n"
"cyiXUwT83Wmmu+WWdcXpH876M1AnW8RtB1aIWNabaszHqI30ySoSqQa8wlqvYqdh" "\n"
"+zYjASRezBXVLDvJ1SNYfsp/0bLA3cym3ZwX84FINTECgYEA6lzm8FgTPhYozZeg" "\n"
"RGg6eIDSrTRIZ2FKP70fFGK5OjemfF1vlTyoijUhtf/v4bA4Qlpz4K1tL0eyyex3" "\n"
"dlDnLC8mzpHFVU2KFNK0my7ssBvg32n4LvuvQujUNIa6MHDM8lcMhoA6jxqQNhPv" "\n"
"Vja/UDMHgosp05HSJE1wBIB/0zsCgYEAzX71SdLd3vBVP8FTug9rNAzbFIBF2jXy" "\n"
"GdySJyjpvehvHVbIVhPjYGP3HtA+sZb83wTwlUWkzEKibegRHANe5MFUxiB7fyui" "\n"
"5jx7UUMrSSF0WW0jWhfjlDXMBlY8E38KCVSBo9UAWQXSzxH5EPxZqq0jeiS2bfvM" "\n"
"1dIciKhTjOkCgYEAwFVt0WD2qcVVxyPgi0NeePZ/71Uw9maJoLV8hCZhDL4PC5FC" "\n"
"uZ8GUiY4fDyGiRktkobZAlJRgLO+rqg5ggfzL/eiSXSoFdGEuIITZiekZwL6EV/O" "\n"
"JgC3XJnnTRQkSQzJpTh7NwaVCEwsfbTufjp/1zmJuECtGsxZQSGsBIXQYXECgYEA" "\n"
"mrPrgapH8iBIbXjjyXz2HfdXrzVqYP6fxqxxMx3v6lJj5FiC9Zp/YP+g+QeZSyT6" "\n"
"NgOIAzis+kFn+wnsZ4R6GgkaAxZNIs39EwuRYvoISkPvTauGI7s8T0W41URycdMA" "\n"
"AUonVulyG5Lww4cqVIlGD+HMhZXB6UbZTFejt5XRYJECgYEA6Bq2rNJqt3EGvxSP" "\n"
"ta4h5l4QXtAAiI7gczoPH0Sn0VENUWMZadq4+B8Lq/uejQK8RMB1FcZSpXmZ0n3V" "\n"
"KRf54NbOaYku6oK1L4ZJEJZ4eJh8k3q35lps6PtOVUevtL3XdbeykpY3Y/R12rdV" "\n"
"Biel7OSo+VEmoTJ9Wm6xFaEmSFU=" "\n"
"-----END PRIVATE KEY-----" "\n";

std::string CertificateRevocationListTest::crlPublicKeyPem = "-----BEGIN PUBLIC KEY-----" "\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvCCfNp9f9MDwoJa/t9TM" "\n"
"XcYjXGFCxpAqhAAzR8bSISzQ/qJdkEqmpIN1bEIWQZGpzeIXp4ZdslpZ2KMJ3OXJ" "\n"
"Wdi7nEOg+F4Kcer+qRzVbjqGoZ5BTRoo8G/GmP/j8R7++vZhVUBSbDZWYA7sytEe" "\n"
"n8HGeiRUXGDGJu2OLAdvgbsgDJr2DdDCNUP/Q8UT+geeikaJNFP7QjvxKJ29qKoR" "\n"
"pUHzy02+tJmHk5xxPHP8TNd0Wqud1Eoa7QGtERxLkkSiPuSYZHoawNzovZRb74cT" "\n"
"TgLs6swCEgA7clquXhGMnfVhO/9o2AezVkLr3x7hJMBSgz4SoPRZKs1F76HHD/yE" "\n"
"swIDAQAB" "\n"
"-----END PUBLIC KEY-----" "\n";

std::string CertificateRevocationListTest::crlWrongPublicKeyPem = "-----BEGIN PUBLIC KEY-----" "\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqaENXPUFvkjledWgw/4C" "\n"
"bdv6v6d8+0DbdzRHGsNEO15XrLZDwC6pNj+GHQX81nrzFA/MlscywErx9Gj74YyD" "\n"
"ONuSf6e+XwFNV0rYd78ndGgNaz3OD+tPT6+6UNv1+JIGGPTdCIhdF5D3PvXIoMiA" "\n"
"iQRQI6jNWMlwGpsJ7E5FhW2dXne0+8tLVm4SmxoTqMfR5MBW0VBAagDc5OLO1Eti" "\n"
"xjm3Z0eoJ2T4JECDGfFD4Biwmbvr2mXuafnr7VhCeHBzEDLM+r6NzocCV8GH25mC" "\n"
"I0h7+2U5ZfqNNzYTfmEpc4zALRvL2HHIxKkWgBStzkO++KSLhZA7b4cFPV1tQfii" "\n"
"IQIDAQAB" "\n"
"-----END PUBLIC KEY-----" "\n";


std::string CertificateRevocationListTest::crlSignatureValue = "iQMnmNLI0KBKL5LymF7VF137GLQ9/ch2yVprhWi28cTg8jR57xY3xQISWoB14raq"
"Ich+FrGLXn8cdVDJNSho6QoVCmLQRMaF2BuF3DaG13zgHVuRmhVRsABC3vxD39tL"
"Ud6tDrVAVB1vPiu8NJKDvxAJScg6CfjvgxfeqOyxP1wgMq5TSEwEd3m0EujzcbvM"
"/x2pEme+VhXKRYLh3P3Al+o7/w7V/SxX7EZOLBKGYnNhtL35kYNR6d5vdc0i5LZF"
"gitrTJsEADskmDavc9aV86F224UCb25aV3qxuqOQ00zqIVrTqv+femi6impYEBfE"
"lT1cORfJV4zZtHroYz0DPQ==";

std::string CertificateRevocationListTest::crlInvalidPem = "-----BEGIN X509 CRL-----" "\n"
"-----END X509 CRL-----" "\n";

PrivateKey CertificateRevocationListTest::crlPrivateKey = PrivateKey(crlPrivateKeyPem);
PublicKey CertificateRevocationListTest::crlPublicKey = PublicKey(crlPublicKeyPem);
PublicKey CertificateRevocationListTest::crlWrongPublicKey = PublicKey(crlWrongPublicKeyPem);

MessageDigest::Algorithm CertificateRevocationListTest::mdAlgorithm = MessageDigest::SHA512;
int CertificateRevocationListTest::serial = 20;
BigInteger CertificateRevocationListTest::serialBigInt = BigInteger(serial);
int CertificateRevocationListTest::version = 1;

std::string CertificateRevocationListTest::rdnIssuerCountry = "BR";
std::string CertificateRevocationListTest::rdnIssuerState = "Sao Paulo";
std::string CertificateRevocationListTest::rdnIssuerLocality = "Sao Paulo";
std::string CertificateRevocationListTest::rdnIssuerOrganization = "Cert Signer";
std::string CertificateRevocationListTest::rdnIssuerCommonName = "Ronaldo Cert Signer V3";

int CertificateRevocationListTest::epochLast = 1487889907;
std::string CertificateRevocationListTest::stampLast = "170223224507Z";
int CertificateRevocationListTest::epochNext = 1665096307;
std::string CertificateRevocationListTest::stampNext = "221006224507Z";

// Serial seems bugged when retrieving from CRL if 16 bytes, need to look further
std::string CertificateRevocationListTest::revSerialOne = "9A3298AFB5AC71C7";
std::string CertificateRevocationListTest::revSerialOneDec = "11111111111111111111";
int CertificateRevocationListTest::revEpochOne = 1487889918;
std::string CertificateRevocationListTest::revStampOne = "170223224518Z";
RevokedCertificate::ReasonCode CertificateRevocationListTest::revReasonOne = RevokedCertificate::KEY_COMPROMISE;

std::string CertificateRevocationListTest::revSerialTwo = "1ED6EB565788E38E";
std::string CertificateRevocationListTest::revSerialTwoDec = "2222222222222222222";
int CertificateRevocationListTest::revEpochTwo = 1487989907;
std::string CertificateRevocationListTest::revStampTwo = "170225023147Z";
RevokedCertificate::ReasonCode CertificateRevocationListTest::revReasonTwo = RevokedCertificate::CA_COMPROMISE;

long CertificateRevocationListTest::baseCrl = 19;
std::string CertificateRevocationListTest::baseCrlString = "19";


/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, SerialNumber) {
    testSerialNumber();
}

TEST_F(CertificateRevocationListTest, SerialNumberBigInt) {
    testSerialNumberBigInt();
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, BaseCRLNumber) {
    testBaseCRLNumber();
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, BaseCRLNumberBigInt) {
    testBaseCRLNumberBigInt();
}


/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, Version) {
    testVersion();
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, Issuer) {
    testIssuer();
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, LastUpdate) {
    testLastUpdate();
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, NextUpdate) {
    testNextUpdate();
}

/**
 * @brief 
 */
TEST_F(CertificateRevocationListTest, RevokedCertificate) {
    testRevokedCertificate();
}

TEST_F(CertificateRevocationListTest, CrlNumberExtension) {
    testExtensionCrlNumber();
}

TEST_F(CertificateRevocationListTest, DeltaCRLIndicatorExtension) {
    testExtensionDeltaCrlIndicator();
}

TEST_F(CertificateRevocationListTest, AuthorityKeyIdentifierExtension) {
    testExtensionAuthorityKeyIdentifier();
}

TEST_F(CertificateRevocationListTest, Verify) {
    testVerifySignature();
}

/**
 * @brief Sanity test with X509_CRL Constructor
 */
TEST_F(CertificateRevocationListTest, FromX509) {
    crl = new CertificateRevocationList(crl->getX509Crl());
    testRevokedCertificate();
}

/**
 * @brief Sanity test with PEM Encoded format
 */
TEST_F(CertificateRevocationListTest, FromPEM) {
    crl = new CertificateRevocationList(crl->getPemEncoded());
    testRevokedCertificate();
}

/**
 * @brief Sanity test with DER Encoded format
 */
TEST_F(CertificateRevocationListTest, FromDER) {
    ByteArray ba;

    ba = crl->getDerEncoded();
    crl = new CertificateRevocationList(ba);
    testRevokedCertificate();
}

/**
 * @brief Sanity test with another CRL Object
 */
TEST_F(CertificateRevocationListTest, FromCRL) {
    CertificateRevocationList rev(crl->getX509Crl());

    crl = new CertificateRevocationList(rev);
    testRevokedCertificate();
}

TEST_F(CertificateRevocationListTest, XMLEncoded) {
    testXmlEncoded();
}

TEST_F(CertificateRevocationListTest, XMLEncodedTab) {
    testXmlEncodedTab();
}

TEST_F(CertificateRevocationListTest, VerifyWrongPublicKey) {
    testVerifySignatureWrongPublicKey();
}

TEST_F(CertificateRevocationListTest, InvalidPEM) {
    testInvalidPem();
}

TEST_F(CertificateRevocationListTest, InvalidDER) {
    testInvalidDER();
}

TEST_F(CertificateRevocationListTest, InvalidCRL) {
    testInvalidCRL();
}