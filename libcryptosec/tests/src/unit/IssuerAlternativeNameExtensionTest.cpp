#include <libcryptosec/certificate/IssuerAlternativeNameExtension.h>
#include <libcryptosec/certificate/Extension.h>
#include <libcryptosec/certificate/GeneralNames.h>
#include <libcryptosec/certificate/GeneralName.h>

#include <sstream>
#include <gtest/gtest.h>


/**
 * @brief Testes unitários da classe IssuerAlternativeNameExtension
 */
class IssuerAlternativeNameExtensionTest : public ::testing::Test {

protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    IssuerAlternativeNameExtension defaultConstructor() {
        IssuerAlternativeNameExtension ret {};
        return ret;
    }

    IssuerAlternativeNameExtension extensionConstructor() {
        this->issuerAltNames = GeneralNames();
        std::vector<GeneralName> gns = genAllNames();
        for (unsigned int i = 0; i < gns.size(); i++) {
            issuerAltNames.addGeneralName(gns.at(i));
        };

        IssuerAlternativeNameExtension altName = defaultConstructor();
        altName.setIssuerAltName(issuerAltNames);
        X509_EXTENSION *ext = altName.getX509Extension();

        IssuerAlternativeNameExtension ret(ext);
        return ret;
    }

    std::vector<GeneralName> genAllNames() {
        std::vector<GeneralName> gns;
      
        GeneralName otherName;
        otherName.setOtherName(otherNameOid, otherNameData);

        GeneralName rfc;
        rfc.setRfc822Name(rfc822Name);

        GeneralName dns;
        dns.setDnsName(dnsName);

        GeneralName directoryName;
        RDNSequence rdn;
        rdn.addEntry(RDNSequence::COMMON_NAME, directoryCN);
        directoryName.setDirectoryName(rdn);

        GeneralName uniformResourceId;
        uniformResourceId.setUniformResourceIdentifier(uri);

        GeneralName ipAddr;
        ipAddr.setIpAddress(ipAddress);

        GeneralName regId;
        ObjectIdentifier oid;
        oid = ObjectIdentifierFactory::getObjectIdentifier(ridOid);
        regId.setRegisteredId(oid);

        gns.push_back(otherName);
        gns.push_back(rfc);
        gns.push_back(dns);
        gns.push_back(directoryName);
        gns.push_back(uniformResourceId);
        gns.push_back(ipAddr);
        gns.push_back(regId);

        return gns;
    }

    void testCompareNames(IssuerAlternativeNameExtension ext) {
        // ext = IssuerAlternativeNameExtesion object previously built and it is the target to be tested
        // exp = Values to be compared to 
        GeneralNames extGN = ext.getIssuerAltName();

        std::vector<GeneralName> extVector = extGN.getGeneralNames();
        std::vector<GeneralName> expVector = issuerAltNames.getGeneralNames();

        ASSERT_EQ(extGN.getNumberOfEntries(), issuerAltNames.getNumberOfEntries());
        for (unsigned int i = 0; i < extVector.size() ; i++) {
            GeneralName ext = extVector.at(i);
            GeneralName exp = expVector.at(i);

            GeneralName::Type extType = ext.getType();
            GeneralName::Type expType = exp.getType();

            ASSERT_EQ(extType, expType);

            switch (extType) {
            case GeneralName::OTHER_NAME:
                ASSERT_EQ(ext.getOtherName(), exp.getOtherName());
                break;
            case GeneralName::RFC_822_NAME:
                ASSERT_EQ(ext.getRfc822Name(), exp.getRfc822Name());
                break;
            case GeneralName::DNS_NAME:
                ASSERT_EQ(ext.getDnsName(), exp.getDnsName());
                break;
            case GeneralName::DIRECTORY_NAME:
            {
                std::vector<std::pair<ObjectIdentifier, std::string> > entries = ext.getDirectoryName().getEntries();
                for (unsigned int i = 0; i < entries.size(); i++) {
                std::pair<ObjectIdentifier, std::string> dataPair = entries.at(i);
                ASSERT_EQ(dataPair.first.getName(), "CN");
                ASSERT_EQ(dataPair.second, directoryCN);
                }
                break;
            }
            case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
                ASSERT_EQ(ext.getUniformResourceIdentifier(), exp.getUniformResourceIdentifier());
                break;
            case GeneralName::IP_ADDRESS:
                ASSERT_EQ(ext.getIpAddress(), exp.getIpAddress());
                break;
            case GeneralName::REGISTERED_ID:
                ASSERT_EQ(ext.getRegisteredId().getOid(), exp.getRegisteredId().getOid());
                break;
            }
        }
    }

    void testXmlEncoded(IssuerAlternativeNameExtension ext) {
        std::string expected = "<issuerAlternativeName>\n" +
            std::string("\t<extnID>issuerAltName</extnID>\n") +
            "\t<critical>no</critical>\n" + 
            "\t<extnValue>\n" +
            "\t\t<generalNames>\n" +
            "\t\t\t<otherName>\n" +
            "\t\t\t\t2.16.76.1.3.3 : 00000000000100\n" +
            "\t\t\t</otherName>\n" +
            "\t\t\t<rfc822Name>\n" +
            "\t\t\t\texample@mail.com\n" +
            "\t\t\t</rfc822Name>\n" +
            "\t\t\t<dnsName>\n" +
            "\t\t\t\t8.8.8.8\n" +
            "\t\t\t</dnsName>\n" +
            "\t\t\t<directoryName>\n" +
            "\t\t\t\t<RDNSequence>\n" +
            "\t\t\t\t\t<commonName>Example Name</commonName>\n" +
            "\t\t\t\t</RDNSequence>\n" +
            "\t\t\t</directoryName>\n" +
            "\t\t\t<uniformResourceIdentifier>\n" +
            "\t\t\t\twww.example.com\n" +
            "\t\t\t</uniformResourceIdentifier>\n" +
            "\t\t\t<iPAddress>\n" +
            "\t\t\t\t127.0.0.1\n" +
            "\t\t\t</iPAddress>\n" +
            "\t\t\t<registeredID>\n" +
            "\t\t\t\tCN\n" +
            "\t\t\t</registeredID>\n" +
            "\t\t</generalNames>\n" +
            "\t</extnValue>\n" +
            "</issuerAlternativeName>\n";
        ASSERT_EQ(ext.getXmlEncoded(), expected);
    }

    void testXmlEncodedTab(IssuerAlternativeNameExtension ext) {
        std::string expected = tab + "<issuerAlternativeName>\n" +
            tab + "\t<extnID>issuerAltName</extnID>\n" +
            tab + "\t<critical>no</critical>\n" + 
            tab + "\t<extnValue>\n" +
            tab + "\t\t<generalNames>\n" +
            tab + "\t\t\t<otherName>\n" +
            tab + "\t\t\t\t2.16.76.1.3.3 : 00000000000100\n" +
            tab + "\t\t\t</otherName>\n" +
            tab + "\t\t\t<rfc822Name>\n" +
            tab + "\t\t\t\texample@mail.com\n" +
            tab + "\t\t\t</rfc822Name>\n" +
            tab + "\t\t\t<dnsName>\n" +
            tab + "\t\t\t\t8.8.8.8\n" +
            tab + "\t\t\t</dnsName>\n" +
            tab + "\t\t\t<directoryName>\n" +
            tab + "\t\t\t\t<RDNSequence>\n" +
            tab + "\t\t\t\t\t<commonName>Example Name</commonName>\n" +
            tab + "\t\t\t\t</RDNSequence>\n" +
            tab + "\t\t\t</directoryName>\n" +
            tab + "\t\t\t<uniformResourceIdentifier>\n" +
            tab + "\t\t\t\twww.example.com\n" +
            tab + "\t\t\t</uniformResourceIdentifier>\n" +
            tab + "\t\t\t<iPAddress>\n" +
            tab + "\t\t\t\t127.0.0.1\n" +
            tab + "\t\t\t</iPAddress>\n" +
            tab + "\t\t\t<registeredID>\n" +
            tab + "\t\t\t\tCN\n" +
            tab + "\t\t\t</registeredID>\n" +
            tab + "\t\t</generalNames>\n" +
            tab + "\t</extnValue>\n" +
            tab + "</issuerAlternativeName>\n";
        ASSERT_EQ(ext.getXmlEncoded(tab), expected);
    }

    void testXmlEncodedEmpty() {
        IssuerAlternativeNameExtension ext;
        std::string expected = "<issuerAlternativeName>\n" +
            std::string("\t<extnID>issuerAltName</extnID>\n") +
            "\t<critical>no</critical>\n" +
            "\t<extnValue>\n" +
            "\t\t<generalNames>\n" +
            "\t\t</generalNames>\n" +
            "\t</extnValue>\n" + 
            "</issuerAlternativeName>\n";
        ASSERT_EQ(ext.getXmlEncoded(), expected);
    }

    void testValue2Xml(IssuerAlternativeNameExtension ext) {
        std::string tab = "";
        std::string expected = tab + "<generalNames>\n" +
            tab + "\t<otherName>\n" +
            tab + "\t\t2.16.76.1.3.3 : 00000000000100\n" +
            tab + "\t</otherName>\n" +
            tab + "\t<rfc822Name>\n" +
            tab + "\t\texample@mail.com\n" +
            tab + "\t</rfc822Name>\n" +
            tab + "\t<dnsName>\n" +
            tab + "\t\t8.8.8.8\n" +
            tab + "\t</dnsName>\n" +
            tab + "\t<directoryName>\n" +
            tab + "\t\t<RDNSequence>\n" +
            tab + "\t\t\t<commonName>Example Name</commonName>\n" +
            tab + "\t\t</RDNSequence>\n" +
            tab + "\t</directoryName>\n" +
            tab + "\t<uniformResourceIdentifier>\n" +
            tab + "\t\twww.example.com\n" +
            tab + "\t</uniformResourceIdentifier>\n" +
            tab + "\t<iPAddress>\n" +
            tab + "\t\t127.0.0.1\n" +
            tab + "\t</iPAddress>\n" +
            tab + "\t<registeredID>\n" +
            tab + "\t\tCN\n" +
            tab + "\t</registeredID>\n" +
            tab + "</generalNames>\n";
        ASSERT_EQ(ext.extValue2Xml(tab), expected);
    }

    void testValue2XmlTab(IssuerAlternativeNameExtension ext) {
        std::string expected = tab + "<generalNames>\n" +
            tab + "\t<otherName>\n" +
            tab + "\t\t2.16.76.1.3.3 : 00000000000100\n" +
            tab + "\t</otherName>\n" +
            tab + "\t<rfc822Name>\n" +
            tab + "\t\texample@mail.com\n" +
            tab + "\t</rfc822Name>\n" +
            tab + "\t<dnsName>\n" +
            tab + "\t\t8.8.8.8\n" +
            tab + "\t</dnsName>\n" +
            tab + "\t<directoryName>\n" +
            tab + "\t\t<RDNSequence>\n" +
            tab + "\t\t\t<commonName>Example Name</commonName>\n" +
            tab + "\t\t</RDNSequence>\n" +
            tab + "\t</directoryName>\n" +
            tab + "\t<uniformResourceIdentifier>\n" +
            tab + "\t\twww.example.com\n" +
            tab + "\t</uniformResourceIdentifier>\n" +
            tab + "\t<iPAddress>\n" +
            tab + "\t\t127.0.0.1\n" +
            tab + "\t</iPAddress>\n" +
            tab + "\t<registeredID>\n" +
            tab + "\t\tCN\n" +
            tab + "\t</registeredID>\n" +
            tab + "</generalNames>\n";
        ASSERT_EQ(ext.extValue2Xml(tab), expected);
    }

    void testValue2XmlEmpty() {
        IssuerAlternativeNameExtension ext;
        std::string expected = "<generalNames>\n</generalNames>\n";
        ASSERT_EQ(ext.extValue2Xml(), expected);
    }

    GeneralNames issuerAltNames;
    static GeneralName issuerAltName;

    static std::string otherNameOid;
    static std::string otherNameData;
    static std::string rfc822Name;
    static std::string dnsName;
    static std::string directoryCN;
    static std::string uri;
    static std::string ipAddress;
    static std::string ridOid;

    static std::string tab;
};

/*
 * Initialization of variables used in the tests
 */
std::string IssuerAlternativeNameExtensionTest::otherNameOid = "2.16.76.1.3.3";
std::string IssuerAlternativeNameExtensionTest::otherNameData = "00000000000100";
std::string IssuerAlternativeNameExtensionTest::rfc822Name = "example@mail.com";
std::string IssuerAlternativeNameExtensionTest::dnsName = "8.8.8.8";
std::string IssuerAlternativeNameExtensionTest::directoryCN = "Example Name";
std::string IssuerAlternativeNameExtensionTest::uri = "www.example.com";
std::string IssuerAlternativeNameExtensionTest::ipAddress = "127.0.0.1";
std::string IssuerAlternativeNameExtensionTest::ridOid = "2.5.4.3";

std::string IssuerAlternativeNameExtensionTest::tab = "tab";

TEST_F(IssuerAlternativeNameExtensionTest, CompareAltNames) {
  testCompareNames(extensionConstructor());
}

TEST_F(IssuerAlternativeNameExtensionTest, Xml) {
  testXmlEncoded(extensionConstructor());
}

TEST_F(IssuerAlternativeNameExtensionTest, XmlTab) {
  testXmlEncodedTab(extensionConstructor());
}

TEST_F(IssuerAlternativeNameExtensionTest, XmlEmpty) {
  testXmlEncodedEmpty();
}

TEST_F(IssuerAlternativeNameExtensionTest, ExtValue2Xml) {
  testValue2Xml(extensionConstructor());
}

TEST_F(IssuerAlternativeNameExtensionTest, ExtValue2XmlTab) {
  testValue2XmlTab(extensionConstructor());
}

TEST_F(IssuerAlternativeNameExtensionTest, ExtValue2XmlEmpty) {
  testValue2XmlEmpty();
}

