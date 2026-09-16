package fixtures;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

class XxeFixture {
    void generalEntityProven(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void parameterEntityProven(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        factory.setAttribute(
                "http://javax.xml.XMLConstants/property/accessExternalDTD", "file");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void externalDtdProven(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature(
                "http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "http");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void multipleProvenPaths(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        factory.setFeature(
                "http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void accessDenyThenAllow(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file,http");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void disallowDoctypeUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void externalGeneralUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void externalParameterUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void externalDtdUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void xIncludeUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setXIncludeAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void expandEntitiesUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void multipleUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        factory.setXIncludeAware(true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void safeThenUnsafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void differentFactories(String xml) throws Exception {
        DocumentBuilderFactory safeFactory = DocumentBuilderFactory.newInstance();
        safeFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilderFactory unsafeFactory = DocumentBuilderFactory.newInstance();
        unsafeFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        unsafeFactory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        unsafeFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder safeBuilder = safeFactory.newDocumentBuilder();
        DocumentBuilder unsafeBuilder = unsafeFactory.newDocumentBuilder();
        safeBuilder.parse(xml);
        unsafeBuilder.parse(xml);
    }

    void differentBuilders(String xml) throws Exception {
        DocumentBuilderFactory unsafeFactory = DocumentBuilderFactory.newInstance();
        unsafeFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        unsafeFactory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        unsafeFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder unsafeBuilder = unsafeFactory.newDocumentBuilder();
        DocumentBuilderFactory safeFactory = DocumentBuilderFactory.newInstance();
        safeFactory.setXIncludeAware(false);
        DocumentBuilder safeBuilder = safeFactory.newDocumentBuilder();
        safeBuilder.parse(xml);
        unsafeBuilder.parse(xml);
    }

    void factoryOnly() {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    }

    void unsafeWithoutParse() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setXIncludeAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
    }

    void safeConfiguration(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void unsafeThenSafe(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void noConfiguration(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void customFactory(String xml) throws Exception {
        CustomDocumentBuilderFactory factory = CustomDocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        CustomDocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void customBuilder(String xml) throws Exception {
        CustomDocumentBuilder builder = new CustomDocumentBuilder();
        builder.parse(xml);
    }

    void configurationAfterBuilder(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        builder.parse(xml);
    }

    void mixedLineage(String xml) throws Exception {
        DocumentBuilderFactory unsafeFactory = DocumentBuilderFactory.newInstance();
        unsafeFactory.setExpandEntityReferences(true);
        DocumentBuilderFactory safeFactory = DocumentBuilderFactory.newInstance();
        safeFactory.setExpandEntityReferences(false);
        DocumentBuilder safeBuilder = safeFactory.newDocumentBuilder();
        safeBuilder.parse(xml);
    }

    void arbitraryFeature(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://example.test/external-general-entities", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void arbitraryBooleanMethod(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void branchAmbiguous(String xml, boolean flag) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        if (flag) {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        } else {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void accessBranchAmbiguous(String xml, boolean flag) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        if (flag) {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        } else {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void loopAmbiguous(String xml, boolean active) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        while (active) {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
            active = false;
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void accessLoopAmbiguous(String xml, boolean active) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        while (active) {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
            active = false;
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void inputStreamOverload(InputStream xml, String systemId) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml, systemId);
    }

    void generalAccessDenied(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void doctypeDeniedGeneral(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void generalUnknown(String xml, boolean externalGeneral) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature(
                "http://xml.org/sax/features/external-general-entities", externalGeneral);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void accessUnknown(String xml, String externalAccess) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, externalAccess);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void generalAccessUnset(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void customAccessProperty(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(
                "http://example.test/property/accessExternalDTD", "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void accessAllowThenDeny(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "   ");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void accessAfterBuilder(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        builder.parse(xml);
    }

    void safeExternalFeaturesWithDoctypeAllowed(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature(
                "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }

    void doctypeDeniedExpand(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }
}

class CustomDocumentBuilderFactory {
    static CustomDocumentBuilderFactory newInstance() {
        return new CustomDocumentBuilderFactory();
    }

    void setFeature(String feature, boolean value) {}

    CustomDocumentBuilder newDocumentBuilder() {
        return new CustomDocumentBuilder();
    }
}

class CustomDocumentBuilder {
    void parse(String xml) {}
}
