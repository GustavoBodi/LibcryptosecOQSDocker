#include <libcryptosec/certificate/Extension.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes unitários da classe Extension
 */
class ExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    Extension generateUnknownExtension() {
      ByteArray extValue = ByteArray(unknownValue);
      return Extension(unknownOid, false, Base64::encode(extValue));
    }

    void testGetObjectIdentifierUnknownExt() {
      Extension ext = generateUnknownExtension();
      ObjectIdentifier oid = ext.getObjectIdentifier();

      ASSERT_EQ(oid.getOid(), unknownOid);
    }

    void testGetNameUnknownExt() {
      Extension ext = generateUnknownExtension();

      ASSERT_EQ(ext.getName(), unknownOid);
    }

    void testGetTypeNameUnknownExt() {
      Extension ext = generateUnknownExtension();

      ASSERT_EQ(ext.getTypeName(), Extension::UNKNOWN);
    }

    void testGetValueUnknownExt() {
      Extension ext = generateUnknownExtension();
      ByteArray ba = ext.getValue();

      ASSERT_EQ(ba.toString(), unknownValue);
    }

    void testGetBase64ValueUnknownExt() {
      Extension ext = generateUnknownExtension();
      ByteArray extValue = ByteArray(unknownValue);

      ASSERT_EQ(ext.getBase64Value(), Base64::encode(extValue));
    }

    void testGetCritical() {
      Extension ext = generateUnknownExtension();

      ASSERT_EQ(ext.isCritical(), false);
    }

    void testSetCritical() {
      Extension ext = generateUnknownExtension();
      ext.setCritical(true);

      ASSERT_EQ(ext.isCritical(), true);
    }

    void testGetX509Extension() {
      Extension ext = generateUnknownExtension();
      X509_EXTENSION *x509 = ext.getX509Extension();
      Extension copy(x509);

      ASSERT_EQ(ext.getObjectIdentifier().getOid(), copy.getObjectIdentifier().getOid());
      ASSERT_EQ(ext.getBase64Value(), copy.getBase64Value());
    }

    void testConstructorNullPointer() {
      ASSERT_THROW(Extension(NULL), CertificationException); 
    }

    static std::string unknownOid;
    static std::string unknownValue;

};

/*
 * Initialization of variables used in the tests
 */
std::string ExtensionTest::unknownOid = "1.2.3.4.5.6.7.8.9.10";
std::string ExtensionTest::unknownValue = "foo bar";

TEST_F(ExtensionTest, GetObjectIdentifierUnknownExt) {
  testGetObjectIdentifierUnknownExt();
}

TEST_F(ExtensionTest, GetNameUnknownExtension) {
  testGetNameUnknownExt();
}

TEST_F(ExtensionTest, GetTypeNameUnknownExtension) {
  testGetTypeNameUnknownExt();
}

TEST_F(ExtensionTest, GetValueUnknownExtension) {
  testGetValueUnknownExt();
}

TEST_F(ExtensionTest, GetBase64ValueUnkownExtension) {
  testGetBase64ValueUnknownExt();
}

TEST_F(ExtensionTest, GetCritical) {
  testGetCritical();
}

TEST_F(ExtensionTest, SetCritical) {
  testSetCritical();
}

TEST_F(ExtensionTest, GetX509Extension) {
  testGetX509Extension();
}

TEST_F(ExtensionTest, ConstructorNullPointer) {
  testConstructorNullPointer();
}
