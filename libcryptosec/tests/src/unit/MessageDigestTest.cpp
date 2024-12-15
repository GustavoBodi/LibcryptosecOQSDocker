#include <libcryptosec/MessageDigest.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe MessageDigest
 */
class MessageDigestTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    std::string initAndDigestData(MessageDigest::Algorithm algorithm) {
      MessageDigest md;

      md.init(algorithm);
      md.update(data);

      return md.doFinal().toHex();
    }

    std::string digestDataString(MessageDigest::Algorithm algorithm) {
      MessageDigest md = MessageDigest(algorithm);

      md.update(data);

      return md.doFinal().toHex();
    }

    std::string digestDataByteArray(MessageDigest::Algorithm algorithm) {
      MessageDigest md = MessageDigest(algorithm);
      ByteArray ba = ByteArray(data);

      md.update(ba);

      return md.doFinal().toHex();
    }

    std::string digestDoFinalString(MessageDigest::Algorithm algorithm) {
      MessageDigest md = MessageDigest(algorithm);

      return md.doFinal(data).toHex();
    }

    std::string digestDoFinalByteArray(MessageDigest::Algorithm algorithm) {
      MessageDigest md = MessageDigest(algorithm);
      ByteArray ba = ByteArray(data);

      return md.doFinal(ba).toHex();
    }

    MessageDigest::Algorithm getAlgorithm(MessageDigest::Algorithm algorithm) {
      MessageDigest md = MessageDigest(algorithm);
      return md.getAlgorithm();
    }

    const EVP_MD* getMessageDigest(MessageDigest::Algorithm algorithm) {
      return MessageDigest::getMessageDigest(algorithm);
    }

    void digestWithoutInit() {
      MessageDigest md;
      md.update(data);
    }

    void doFinalWithoutInit() {
      MessageDigest md;
      md.doFinal();
    }

    void doFinalWithoutDigest() {
      MessageDigest md = MessageDigest(MessageDigest::SHA256);
      md.doFinal();
    }

    void getAlgorithmWithoutInit() {
      MessageDigest md;
      md.getAlgorithm();
    }

    ObjectIdentifier getMessageDigestOid(MessageDigest::Algorithm algorithm) {
      return MessageDigest::getMessageDigestOid(algorithm);
    }

    MessageDigest::Algorithm getMessageDigestAlgorithm(int nid) {
      return MessageDigest::getMessageDigest(nid);
    }

    void testInitAndDigestMD4() {
      ASSERT_EQ(initAndDigestData(MessageDigest::MD4), digestMD4);
    }

    void testInitAndDigestMD5() {
      ASSERT_EQ(initAndDigestData(MessageDigest::MD5), digestMD5);
    }

    void testInitAndDigestRIPEMD160() {
      ASSERT_EQ(initAndDigestData(MessageDigest::RIPEMD160), digestRIPEMD160);
    }

    void testInitAndDigestSHA1() {
      ASSERT_EQ(initAndDigestData(MessageDigest::SHA1), digestSHA1);
    }

    void testInitAndDigestSHA224() {
      ASSERT_EQ(initAndDigestData(MessageDigest::SHA224), digestSHA224);
    }

    void testInitAndDigestSHA256() {
      ASSERT_EQ(initAndDigestData(MessageDigest::SHA256), digestSHA256);
    }

    void testInitAndDigestSHA384() {
      ASSERT_EQ(initAndDigestData(MessageDigest::SHA384), digestSHA384);
    }

    void testInitAndDigestSHA512() {
      ASSERT_EQ(initAndDigestData(MessageDigest::SHA512), digestSHA512);
    }

    void testDigestStringMD4() {
      ASSERT_EQ(digestDataString(MessageDigest::MD4), digestMD4);
    }

    void testDigestStringMD5() {
      ASSERT_EQ(digestDataString(MessageDigest::MD5), digestMD5);
    }

    void testDigestStringRIPEMD160() {
      ASSERT_EQ(digestDataString(MessageDigest::RIPEMD160), digestRIPEMD160);
    }

    void testDigestStringSHA1() {
      ASSERT_EQ(digestDataString(MessageDigest::SHA1), digestSHA1);
    }

    void testDigestStringSHA224() {
      ASSERT_EQ(digestDataString(MessageDigest::SHA224), digestSHA224);
    }

    void testDigestStringSHA256() {
      ASSERT_EQ(digestDataString(MessageDigest::SHA256), digestSHA256);
    }

    void testDigestStringSHA384() {
      ASSERT_EQ(digestDataString(MessageDigest::SHA384), digestSHA384);
    }

    void testDigestStringSHA512() {
      ASSERT_EQ(digestDataString(MessageDigest::SHA512), digestSHA512);
    }

    void testDigestByteArrayMD4() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::MD4), digestMD4);
    }

    void testDigestByteArrayMD5() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::MD5), digestMD5);
    }

    void testDigestByteArrayRIPEMD160() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::RIPEMD160), digestRIPEMD160);
    }

    void testDigestByteArraySHA1() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::SHA1), digestSHA1);
    }

    void testDigestByteArraySHA224() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::SHA224), digestSHA224);
    }

    void testDigestByteArraySHA256() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::SHA256), digestSHA256);
    }

    void testDigestByteArraySHA384() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::SHA384), digestSHA384);
    }

    void testDigestByteArraySHA512() {
      ASSERT_EQ(digestDataByteArray(MessageDigest::SHA512), digestSHA512);
    }

    void testDoFinalStringMD4() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::MD4), digestMD4);
    }

    void testDoFinalStringMD5() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::MD5), digestMD5);
    }

    void testDoFinalStringRIPEMD160() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::RIPEMD160), digestRIPEMD160);
    }

    void testDoFinalStringSHA1() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::SHA1), digestSHA1);
    }

    void testDoFinalStringSHA224() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::SHA224), digestSHA224);
    }

    void testDoFinalStringSHA256() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::SHA256), digestSHA256);
    }

    void testDoFinalStringSHA384() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::SHA384), digestSHA384);
    }

    void testDoFinalStringSHA512() {
      ASSERT_EQ(digestDoFinalString(MessageDigest::SHA512), digestSHA512);
    }

    void testDoFinalByteArrayMD4() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::MD4), digestMD4);
    }

    void testDoFinalByteArrayMD5() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::MD5), digestMD5);
    }

    void testDoFinalByteArrayRIPEMD160() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::RIPEMD160), digestRIPEMD160);
    }

    void testDoFinalByteArraySHA1() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::SHA1), digestSHA1);
    }

    void testDoFinalByteArraySHA224() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::SHA224), digestSHA224);
    }

    void testDoFinalByteArraySHA256() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::SHA256), digestSHA256);
    }

    void testDoFinalByteArraySHA384() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::SHA384), digestSHA384);
    }

    void testDoFinalByteArraySHA512() {
      ASSERT_EQ(digestDoFinalByteArray(MessageDigest::SHA512), digestSHA512);
    }

    void testGetAlgorithmMD4() {
      ASSERT_EQ(getAlgorithm(MessageDigest::MD4), MessageDigest::MD4);
    }

    void testGetAlgorithmMD5() {
      ASSERT_EQ(getAlgorithm(MessageDigest::MD5), MessageDigest::MD5);
    }

    void testGetAlgorithmRIPEMD160() {
      ASSERT_EQ(getAlgorithm(MessageDigest::RIPEMD160), MessageDigest::RIPEMD160);
    }

    void testGetAlgorithmSHA1() {
      ASSERT_EQ(getAlgorithm(MessageDigest::SHA1), MessageDigest::SHA1);
    }

    void testGetAlgorithmSHA224() {
      ASSERT_EQ(getAlgorithm(MessageDigest::SHA224), MessageDigest::SHA224);
    }

    void testGetAlgorithmSHA256() {
      ASSERT_EQ(getAlgorithm(MessageDigest::SHA256), MessageDigest::SHA256);
    }

    void testGetAlgorithmSHA384() {
      ASSERT_EQ(getAlgorithm(MessageDigest::SHA384), MessageDigest::SHA384);
    }

    void testGetAlgorithmSHA512() {
      ASSERT_EQ(getAlgorithm(MessageDigest::SHA512), MessageDigest::SHA512);
    }

    void testGetMessageDigestMD4() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::MD4)), NID_md4);
    }

    void testGetMessageDigestMD5() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::MD5)), NID_md5);
    }

    void testGetMessageDigestRIPEMD160() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::RIPEMD160)), NID_ripemd160);
    }

    void testGetMessageDigestSHA1() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::SHA1)), NID_sha1);
    }

    void testGetMessageDigestSHA224() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::SHA224)), NID_sha224);
    }

    void testGetMessageDigestSHA256() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::SHA256)), NID_sha256);
    }

    void testGetMessageDigestSHA384() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::SHA384)), NID_sha384);
    }

    void testGetMessageDigestSHA512() {
      ASSERT_EQ(EVP_MD_type(getMessageDigest(MessageDigest::SHA512)), NID_sha512);
    }

    void testGetMessageDigestOidMD4() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::MD4).getNid(), NID_md4);
    }

    void testGetMessageDigestOidMD5() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::MD5).getNid(), NID_md5);
    }

    void testGetMessageDigestOidRIPEMD160() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::RIPEMD160).getNid(), NID_ripemd160);
    }

    void testGetMessageDigestOidSHA1() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::SHA1).getNid(), NID_sha1);
    }

    void testGetMessageDigestOidSHA224() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::SHA224).getNid(), NID_sha224);
    }

    void testGetMessageDigestOidSHA256() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::SHA256).getNid(), NID_sha256);
    }

    void testGetMessageDigestOidSHA384() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::SHA384).getNid(), NID_sha384);
    }

    void testGetMessageDigestOidSHA512() {
      ASSERT_EQ(getMessageDigestOid(MessageDigest::SHA512).getNid(), NID_sha512);
    }

    void testGetMessageDigestAlgorithmMD4() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_md4), MessageDigest::MD4);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_md4WithRSAEncryption), MessageDigest::MD4);
    }

    void testGetMessageDigestAlgorithmMD5() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_md5), MessageDigest::MD5);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_md5WithRSA), MessageDigest::MD5);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_md5WithRSAEncryption), MessageDigest::MD5);
    }

    void testGetMessageDigestAlgorithmRIPEMD160() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ripemd160), MessageDigest::RIPEMD160);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ripemd160WithRSA), MessageDigest::RIPEMD160);
    }

    void testGetMessageDigestAlgorithmSHA1() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_dsaWithSHA1), MessageDigest::SHA1);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_sha1WithRSAEncryption), MessageDigest::SHA1);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_sha1WithRSA), MessageDigest::SHA1);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ecdsa_with_SHA1), MessageDigest::SHA1);
    }

    void testGetMessageDigestAlgorithmSHA224() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_sha224WithRSAEncryption), MessageDigest::SHA224);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ecdsa_with_SHA224), MessageDigest::SHA224);
    }

    void testGetMessageDigestAlgorithmSHA256() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_sha256WithRSAEncryption), MessageDigest::SHA256);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ecdsa_with_SHA256), MessageDigest::SHA256);
    }

    void testGetMessageDigestAlgorithmSHA384() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_sha384WithRSAEncryption), MessageDigest::SHA384);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ecdsa_with_SHA384), MessageDigest::SHA384);
    }

    void testGetMessageDigestAlgorithmSHA512() {
      ASSERT_EQ(getMessageDigestAlgorithm(NID_sha512WithRSAEncryption), MessageDigest::SHA512);
      ASSERT_EQ(getMessageDigestAlgorithm(NID_ecdsa_with_SHA512), MessageDigest::SHA512);
    }

    void testDigestWithoutInit() {
      ASSERT_THROW(digestWithoutInit(), InvalidStateException);
    }

    void testDoFinalWithoutInit() {
      ASSERT_THROW(doFinalWithoutInit(), InvalidStateException);
    }

    void testDoFinalWithoutDigest() {
      ASSERT_THROW(doFinalWithoutDigest(), InvalidStateException);
    }

    void testGetAlgorithmWithoutInit() {
      ASSERT_THROW(getAlgorithmWithoutInit(), InvalidStateException);
    }

    void testGetMessageDigestAlgorithmInvalidAlgorithm() {
      ASSERT_THROW(getMessageDigestAlgorithm(1), MessageDigestException);
    }

    static std::string data;
    static std::string diffData;
    static std::string digestMD4;
    static std::string digestMD5;
    static std::string digestRIPEMD160;
    static std::string digestSHA1;
    static std::string digestSHA224;
    static std::string digestSHA256;
    static std::string digestSHA384;
    static std::string digestSHA512;
    static std::string digestUpdate;

};

/*
 * Initialization of variables used in the tests
 */
std::string MessageDigestTest::data = "Forward and back, and then forward and back";
std::string MessageDigestTest::diffData = " and then go forward and back and put one foot forward";
std::string MessageDigestTest::digestMD4 = "C05829701FE5918467D8D0166BAA6766";
std::string MessageDigestTest::digestMD5 = "ADA35AF7AC7C12C38E9DEB7CEC150577";
std::string MessageDigestTest::digestRIPEMD160 = "38D5101C300848D33C54DCEA8ADEC5F1EE9EFD68";
std::string MessageDigestTest::digestSHA1 = "A8C8D02AEC5176C35FD33D06ACD240DD7D770F46";
std::string MessageDigestTest::digestSHA224 = "7DAADCD21C751B5A238D279678FD6CBD4B2A9E0218588873FF5EBC90";
std::string MessageDigestTest::digestSHA256 = "7D3E352CA398B3B9E756B40D39104B055C9F5CAE53E7F173C48FC31AB5461453";
std::string MessageDigestTest::digestSHA384 = "E13CFB6DC40136A41030853BAD3D456448E98D4979A14D77C85BDA4755C5217C"
                                              "67059A640BAA039946FC8723748D2D71";
std::string MessageDigestTest::digestSHA512 = "1975D01DA9077C7271833747AF633250000D71D46E4287BD903E77198662CAF3"
                                              "5BA6B0837309BD47338F4E94DA76B1CB1E86F2385E66E37669C9845A5665C60E";
std::string MessageDigestTest::digestUpdate = "14F515D0DD290CAE5608698CAD05D4F409D13ECABC7D94731DB8CCD30ABE9E4E";

TEST_F(MessageDigestTest, InitAndDigestMD4) {
  testInitAndDigestMD4();
}

TEST_F(MessageDigestTest, InitAndDigestMD5) {
  testInitAndDigestMD5();
}

TEST_F(MessageDigestTest, InitAndDigestRIPEMD160) {
  testInitAndDigestRIPEMD160();
}

TEST_F(MessageDigestTest, InitAndDigestSHA1) {
  testInitAndDigestSHA1();
}

TEST_F(MessageDigestTest, InitAndDigestSHA224) {
  testInitAndDigestSHA224();
}

TEST_F(MessageDigestTest, InitAndDigestSHA256) {
  testInitAndDigestSHA256();
}

TEST_F(MessageDigestTest, InitAndDigestSHA384) {
  testInitAndDigestSHA384();
}

TEST_F(MessageDigestTest, InitAndDigestSHA512) {
  testInitAndDigestSHA512();
}

TEST_F(MessageDigestTest, DigestStringMD4) {
  testDigestStringMD4();
}

TEST_F(MessageDigestTest, DigestStringMD5) {
  testDigestStringMD5();
}

TEST_F(MessageDigestTest, DigestStringRIPEMD160) {
  testDigestStringRIPEMD160();
}

TEST_F(MessageDigestTest, DigestStringSHA1) {
  testDigestStringSHA1();
}

TEST_F(MessageDigestTest, DigestStringSHA224) {
  testDigestStringSHA224();
}

TEST_F(MessageDigestTest, DigestStringSHA256) {
  testDigestStringSHA256();
}

TEST_F(MessageDigestTest, DigestStringSHA384) {
  testDigestStringSHA384();
}

TEST_F(MessageDigestTest, DigestStringSHA512) {
  testDigestStringSHA512();
}

TEST_F(MessageDigestTest, DigestByteArrayMD4) {
  testDigestByteArrayMD4();
}

TEST_F(MessageDigestTest, DigestByteArrayMD5) {
  testDigestByteArrayMD5();
}

TEST_F(MessageDigestTest, DigestByteArrayRIPEMD160) {
  testDigestByteArrayRIPEMD160();
}

TEST_F(MessageDigestTest, DigestByteArraySHA1) {
  testDigestByteArraySHA1();
}

TEST_F(MessageDigestTest, DigestByteArraySHA224) {
  testDigestByteArraySHA224();
}

TEST_F(MessageDigestTest, DigestByteArraySHA256) {
  testDigestByteArraySHA256();
}

TEST_F(MessageDigestTest, DigestByteArraySHA384) {
  testDigestByteArraySHA384();
}

TEST_F(MessageDigestTest, DigestByteArraySHA512) {
  testDigestByteArraySHA512();
}

TEST_F(MessageDigestTest, DoFinalStringMD4) {
  testDoFinalStringMD4();
}

TEST_F(MessageDigestTest, DoFinalStringMD5) {
  testDoFinalStringMD5();
}

TEST_F(MessageDigestTest, DoFinalStringRIPEMD160) {
  testDoFinalStringRIPEMD160();
}

TEST_F(MessageDigestTest, DoFinalStringSHA1) {
  testDoFinalStringSHA1();
}

TEST_F(MessageDigestTest, DoFinalStringSHA224) {
  testDoFinalStringSHA224();
}

TEST_F(MessageDigestTest, DoFinalStringSHA256) {
  testDoFinalStringSHA256();
}

TEST_F(MessageDigestTest, DoFinalStringSHA384) {
  testDoFinalStringSHA384();
}

TEST_F(MessageDigestTest, DoFinalStringSHA512) {
  testDoFinalStringSHA512();
}

TEST_F(MessageDigestTest, DoFinalByteArrayMD4) {
  testDoFinalByteArrayMD4();
}

TEST_F(MessageDigestTest, DoFinalByteArrayMD5) {
  testDoFinalByteArrayMD5();
}

TEST_F(MessageDigestTest, DoFinalByteArrayRIPEMD160) {
  testDoFinalByteArrayRIPEMD160();
}

TEST_F(MessageDigestTest, DoFinalByteArraySHA1) {
  testDoFinalByteArraySHA1();
}

TEST_F(MessageDigestTest, DoFinalByteArraySHA224) {
  testDoFinalByteArraySHA224();
}

TEST_F(MessageDigestTest, DoFinalByteArraySHA256) {
  testDoFinalByteArraySHA256();
}

TEST_F(MessageDigestTest, DoFinalByteArraySHA384) {
  testDoFinalByteArraySHA384();
}

TEST_F(MessageDigestTest, DoFinalByteArraySHA512) {
  testDoFinalByteArraySHA512();
}

TEST_F(MessageDigestTest, GetAlgorithmMD4) {
  testGetAlgorithmMD4();
}

TEST_F(MessageDigestTest, GetAlgorithmMD5) {
  testGetAlgorithmMD5();
}

TEST_F(MessageDigestTest, GetAlgorithmRIPEMD160) {
  testGetAlgorithmRIPEMD160();
}

TEST_F(MessageDigestTest, GetAlgorithmSHA1) {
  testGetAlgorithmSHA1();
}

TEST_F(MessageDigestTest, GetAlgorithmSHA224) {
  testGetAlgorithmSHA224();
}

TEST_F(MessageDigestTest, GetAlgorithmSHA256) {
  testGetAlgorithmSHA256();
}

TEST_F(MessageDigestTest, GetAlgorithmSHA384) {
  testGetAlgorithmSHA384();
}

TEST_F(MessageDigestTest, GetAlgorithmSHA512) {
  testGetAlgorithmSHA512();
}

TEST_F(MessageDigestTest, GetMessageDigestMD4) {
  testGetMessageDigestMD4();
}

TEST_F(MessageDigestTest, GetMessageDigestMD5) {
  testGetMessageDigestMD5();
}

TEST_F(MessageDigestTest, GetMessageDigestRIPEMD160) {
  testGetMessageDigestRIPEMD160();
}

TEST_F(MessageDigestTest, GetMessageDigestSHA1) {
  testGetMessageDigestSHA1();
}

TEST_F(MessageDigestTest, GetMessageDigestSHA224) {
  testGetMessageDigestSHA224();
}

TEST_F(MessageDigestTest, GetMessageDigestSHA256) {
  testGetMessageDigestSHA256();
}

TEST_F(MessageDigestTest, GetMessageDigestSHA384) {
  testGetMessageDigestSHA384();
}

TEST_F(MessageDigestTest, GetMessageDigestSHA512) {
  testGetMessageDigestSHA512();
}

TEST_F(MessageDigestTest, GetMessageDigestOidMD4) {
  testGetMessageDigestOidMD4();
}

TEST_F(MessageDigestTest, GetMessageDigestOidMD5) {
  testGetMessageDigestOidMD5();
}

TEST_F(MessageDigestTest, GetMessageDigestOidRIPEMD160) {
  testGetMessageDigestOidRIPEMD160();
}

TEST_F(MessageDigestTest, GetMessageDigestOidSHA1) {
  testGetMessageDigestOidSHA1();
}

TEST_F(MessageDigestTest, GetMessageDigestOidSHA224) {
  testGetMessageDigestOidSHA224();
}

TEST_F(MessageDigestTest, GetMessageDigestOidSHA256) {
  testGetMessageDigestOidSHA256();
}

TEST_F(MessageDigestTest, GetMessageDigestOidSHA384) {
  testGetMessageDigestOidSHA384();
}

TEST_F(MessageDigestTest, GetMessageDigestOidSHA512) {
  testGetMessageDigestOidSHA512();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmMD4) {
  testGetMessageDigestAlgorithmMD4();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmMD5) {
  testGetMessageDigestAlgorithmMD5();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmRIPEMD160) {
  testGetMessageDigestAlgorithmRIPEMD160();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmSHA1) {
  testGetMessageDigestAlgorithmSHA1();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmSHA224) {
  testGetMessageDigestAlgorithmSHA224();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmSHA256) {
  testGetMessageDigestAlgorithmSHA256();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmSHA384) {
  testGetMessageDigestAlgorithmSHA384();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmSHA512) {
  testGetMessageDigestAlgorithmSHA512();
}

TEST_F(MessageDigestTest, UpdateWithoutInit) {
  testDigestWithoutInit();
}

TEST_F(MessageDigestTest, DoFinalWithoutInit) {
  testDoFinalWithoutInit();
}

TEST_F(MessageDigestTest, DoFinalWithoutDigest) {
  testDoFinalWithoutDigest();
}

TEST_F(MessageDigestTest, GetAlgorithmWithoutInit) {
  testGetAlgorithmWithoutInit();
}

TEST_F(MessageDigestTest, GetMessageDigestAlgorithmInvalid) {
  testGetMessageDigestAlgorithmInvalidAlgorithm();
}
