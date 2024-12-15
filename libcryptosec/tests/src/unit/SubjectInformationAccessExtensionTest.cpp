#include <libcryptosec/certificate/SubjectInformationAccessExtension.h>
#include <libcryptosec/certificate/Extension.h>
#include <libcryptosec/certificate/AccessDescription.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <sstream>
#include <gtest/gtest.h>

/**
 * @brief Testes unitários da classe SubjectInformationAccessExtension
 */

class SubjectInformationAccessExtensionTest : public ::testing::Test {

protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
  }

  SubjectInformationAccessExtension defaultConstructor() {
    SubjectInformationAccessExtension ret {};
    return ret;
  }

  SubjectInformationAccessExtension extensionConstructor() {
    SubjectInformationAccessExtension sia = defaultConstructor();
    AccessDescription ads = genAccessDescriptions();
    sia.addAccessDescription(ads);
    X509_EXTENSION* ext = sia.getX509Extension();

    SubjectInformationAccessExtension ret(ext);
    return ret;
  }

  GeneralName genRfc822NameGN() {
    GeneralName gn;
    gn.setRfc822Name(rfc822Name);
    return gn;
  }

  ObjectIdentifier genOid() {
    return ObjectIdentifierFactory::getObjectIdentifier(oid);
  }

  AccessDescription genAccessDescriptions() {
    GeneralName gn = genRfc822NameGN();
    ObjectIdentifier obj = genOid();
    AccessDescription ad;

    ad.setAccessLocation(gn);
    ad.setAccessMethod(obj);

    return ad;
  };

  void testSetAccessDescription(SubjectInformationAccessExtension ext) {
    GeneralName extRfc = ext.getAccessDescriptions().at(0).getAccessLocation();
    ObjectIdentifier extObj = ext.getAccessDescriptions().at(0).getAccessMethod();

    ASSERT_EQ(extRfc.getRfc822Name(), rfc822Name);
    ASSERT_EQ(extRfc.getType(), GeneralName::RFC_822_NAME);

    ASSERT_EQ(extObj.getOid(), oid);
    ASSERT_EQ(extObj.getNid(), NID_sinfo_access);
    ASSERT_EQ(extObj.getName(), "subjectInfoAccess");
  }

  void testXmlEncoded(SubjectInformationAccessExtension ext) {
    std::string tab = "";
    std::string expected = tab + "<subjectInformationAccess>\n" +
      tab + "\t<extnID>subjectInfoAccess</extnID>\n" +
      tab + "\t<critical>no</critical>\n" +
      tab + "\t<extnValue>\n" +
      tab + "\t\t<accessDescriptions>\n" +
      tab + "\t\t</accessDescriptions>\n" +
      tab + "\t</extnValue>\n" + 
      tab + "</subjectInformationAccess>\n";
    ASSERT_EQ(ext.getXmlEncoded(), expected);
  }

  void testXmlEncodedTab(SubjectInformationAccessExtension ext) {
    std::string expected = tab + "<subjectInformationAccess>\n" +
      tab + "\t<extnID>subjectInfoAccess</extnID>\n" +
      tab + "\t<critical>no</critical>\n" +
      tab + "\t<extnValue>\n" +
      tab + "\t\t<accessDescriptions>\n" +
      tab + "\t\t</accessDescriptions>\n" +
      tab + "\t</extnValue>\n" + 
      tab + "</subjectInformationAccess>\n";
    ASSERT_EQ(ext.getXmlEncoded(tab), expected);
  }

  void testValue2Xml(SubjectInformationAccessExtension ext) {
    std::string tab = "";
    std::string expected = tab + "<accessDescriptions>\n" +
      tab + "\t<accessDescription>\n" +
      tab + "\t\t<oid>" +
      tab + oid +
      tab + "</oid>\n" +
      tab + "\t\t<rfc822Name>\n" +
      tab + "\t\t\t" + rfc822Name + "\n" +
      tab + "\t\t</rfc822Name>\n" +
      tab + "\t</accessDescription>\n" +
      tab + "</accessDescriptions>\n";
    ASSERT_EQ(ext.extValue2Xml(), expected);
  }


  void testValue2XmlTab(SubjectInformationAccessExtension ext) {
    std::string expected = tab + "<accessDescriptions>\n" +
      tab + "\t<accessDescription>\n" +
      tab + "\t\t<oid>" + oid + "</oid>\n" +
      tab + "\t\t<rfc822Name>\n" +
      tab + "\t\t\t" + rfc822Name + "\n" +
      tab + "\t\t</rfc822Name>\n" +
      tab + "\t</accessDescription>\n" +
      tab + "</accessDescriptions>\n";
    ASSERT_EQ(ext.extValue2Xml(tab), expected);
  }

  static std::string rfc822Name;
  static std::string oid;
  static std::string tab;
};

/*
 * Initialization of variables used in the tests
 */
std::string SubjectInformationAccessExtensionTest::rfc822Name = "example@mail.com";
std::string SubjectInformationAccessExtensionTest::oid = "1.3.6.1.5.5.7.1.11";
std::string SubjectInformationAccessExtensionTest::tab = "tab";

TEST_F(SubjectInformationAccessExtensionTest, SetAccessDescription) {
  testSetAccessDescription(extensionConstructor());
}

TEST_F(SubjectInformationAccessExtensionTest, Xml) {
  testXmlEncoded(defaultConstructor());
}

TEST_F(SubjectInformationAccessExtensionTest, XmlTab) {
  testXmlEncodedTab(defaultConstructor());
}

TEST_F(SubjectInformationAccessExtensionTest, Value2Xml) {
  testValue2Xml(extensionConstructor());
}

TEST_F(SubjectInformationAccessExtensionTest, Value2XmlTab) {
  testValue2XmlTab(extensionConstructor());
}
