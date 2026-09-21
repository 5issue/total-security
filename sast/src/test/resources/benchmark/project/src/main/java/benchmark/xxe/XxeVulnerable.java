package benchmark.xxe;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.RequestBody;

class XxeVulnerable {
    void parse(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(
                "http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature(
                "http://xml.org/sax/features/external-general-entities", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }
}
