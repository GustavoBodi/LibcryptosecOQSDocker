#include <libcryptosec/certificate/CRLNumberExtension.h>

#include <sstream>
#include <gtest/gtest.h>
#include <stdlib.h>

/**
 * @brief Testes da classe CRLNumberExtension
 */
class CRLNumberExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {
        ext = new CRLNumberExtension(serial);
    }

    virtual void TearDown() {
        if (ext) {
            free(ext);
        }
    }

    /**
     * @brief Generates the expected value when calling ExtValue2Xml
     * @param tab string to insert tabs on the XML value
     */
    std::string genExtValue2Xml(std::string tab = "") {
        std::string ret = tab + "\t<crlNumber>" + std::to_string(serial) + "</crlNumber>" + "\n";

        return ret;
    }

    /**
     * @brief Generates the expected value when calling getXmlEncoded
     * @param tab string to insert tabs on the XML value
     */
    std::string genXml(std::string tab = "") {
        std::string ret = tab + "<crlNumber>" + "\n";

        ret += tab + "\t<extnID>" + extensionName + "</extnID>" + "\n";
        ret += tab + "\t<critical>" + "no" + "</critical>" + "\n";
        ret += tab + "\t<extnValue>" + "\n";
        ret += genExtValue2Xml(tab + "\t");
        ret += tab + "\t</extnValue>" + "\n";
        ret += tab + "</crlNumber>" + "\n";

        return ret;

    }

    /**
     * @brief Tests value from getSerial with default constructor
     */
    void testConstructor() {
        ASSERT_EQ(ext->getSerial(), serial);
    }

    /**
     * @brief Tests setting a value with setSerial and getting it after
     */
    void testSetSerial() {
        ext->setSerial(otherSerial);

        ASSERT_EQ(ext->getSerial(), otherSerial);
    }

    /**
     * @brief Tests the format and value of ExtValue2Xml
     */
    void testExtValue2Xml() {
        std::string xml = genExtValue2Xml();

        ASSERT_EQ(ext->extValue2Xml(), xml);
    }

    /**
     * @brief Tests the format and value of ExtValue2Xml when inserting a tab
     */
    void testExtValue2XmlTab() {
        std::string tab = "tab";
        std::string xml = genExtValue2Xml(tab);

        ASSERT_EQ(ext->extValue2Xml(tab), xml);
    }

    /**
     * @brief Tests the format and values of XML Encoded
     */
    void testGetXmlEncoded() {
        std::string xml = genXml();

        ASSERT_EQ(ext->getXmlEncoded(), xml);
    }

    /**
     * @brief Tests the format and values of XML Encoded when inserting a tab
     */
    void testGetXmlEncodedTab() {
        std::string tab = "tab";
        std::string xml = genXml(tab);

        ASSERT_EQ(ext->getXmlEncoded(tab), xml);
    }

    /**
     * @brief Sanity test with GetX509Extension and X509_EXTENSION constructor
     */
    void testX509Extension() {
        X509_EXTENSION *x509 = ext->getX509Extension();
        CRLNumberExtension *copy = new CRLNumberExtension(x509);

        ASSERT_EQ(copy->getSerial(), serial);

        free(copy);
    }

    /**
     * @brief Tests if extension has the correct OID
     */
    void testGetOid() {
        ObjectIdentifier extOid = ext->getObjectIdentifier();

        ASSERT_EQ(extOid.getOid(), oid);
    }

    /**
     * @brief Tests if extension has the correct TypeName
     */
    void testGetTypeName() {
        ASSERT_EQ(ext->getTypeName(), extensionTypeName);
    }

    /**
     * @brief Tests if extension has the correct name
     */
    void testGetName() {
        ASSERT_EQ(ext->getName(), extensionName);
    }

    /**
     * @brief Tests default value of isCritical (should be false)
     */
    void testIsCritical() {
        ASSERT_EQ(ext->isCritical(), false);
    }

    /**
     * @brief Tests if setCritical changes the isCritical value
     */
    void testSetCritical() {
        ext->setCritical(true);

        ASSERT_EQ(ext->isCritical(), true);
    }

    /**
     * @brief Tests X509_EXTENSION constructor when handling by a null pointer
     */
    void testConstructorX509ExtensionNull() {
        X509_EXTENSION *x509 = NULL;
        ASSERT_THROW(CRLNumberExtension extNull = CRLNumberExtension(x509), CertificationException);
    }

    CRLNumberExtension *ext;
    
    static std::string oid;
    static long serial;
    static long otherSerial;

    static Extension::Name extensionTypeName;
    static std::string extensionName;
};

/*
 * Initialization of variables used in the tests
 */
std::string CRLNumberExtensionTest::oid = "2.5.29.20";
long CRLNumberExtensionTest::serial = 517;
long CRLNumberExtensionTest::otherSerial = 518;

Extension::Name CRLNumberExtensionTest::extensionTypeName = Extension::CRL_NUMBER;
std::string CRLNumberExtensionTest::extensionName = "crlNumber";

TEST_F(CRLNumberExtensionTest, Constructor) {
    testConstructor();
}

TEST_F(CRLNumberExtensionTest, SetSerial) {
    testSetSerial();
}

TEST_F(CRLNumberExtensionTest, ExtValue2Xml) {
    testExtValue2Xml();
}

TEST_F(CRLNumberExtensionTest, ExtValue2XmlTab) {
    testExtValue2XmlTab();
}

TEST_F(CRLNumberExtensionTest, XMLEncoded) {
    testGetXmlEncoded();
}

TEST_F(CRLNumberExtensionTest, XMLEncodedTab) {
    testGetXmlEncodedTab();
}

TEST_F(CRLNumberExtensionTest, X509Extension) {
    testX509Extension();
}

TEST_F(CRLNumberExtensionTest, GetOid) {
    testGetOid();
}

TEST_F(CRLNumberExtensionTest, GetName) {
    testGetName();
}

TEST_F(CRLNumberExtensionTest, GetTypeName) {
    testGetTypeName();
}

TEST_F(CRLNumberExtensionTest, IsCritical) {
    testIsCritical();
}

TEST_F(CRLNumberExtensionTest, SetCritical) {
    testSetCritical();
}

TEST_F(CRLNumberExtensionTest, X509ExtensionNull) {
    testConstructorX509ExtensionNull();
}
