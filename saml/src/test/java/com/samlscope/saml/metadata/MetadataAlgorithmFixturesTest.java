package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;

class MetadataAlgorithmFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static final String SHA256="http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String SHA384="http://www.w3.org/2001/04/xmldsig-more#sha384";
    private static final String RSA256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String RSA384="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

    @Test void orderControlsAndPerTypeRoleOverridesRemainDistinguishable() {
        var service=new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory,Clock.systemUTC()),new XmlSigner(),Clock.systemUTC());
        for(boolean polling:new boolean[]{false,true}) {
            var first=generate(service,MetadataService.Variant.ALGORITHM_ENTITY_ORDER_256_384,polling);
            var reverse=generate(service,MetadataService.Variant.ALGORITHM_ENTITY_ORDER_384_256,polling);
            assertEquals(List.of(SHA256,SHA384),methods(first,"DigestMethod"));
            assertEquals(List.of(SHA384,SHA256),methods(reverse,"DigestMethod"));
            assertEquals(List.of(RSA256,RSA384),methods(first,"SigningMethod"));
            assertEquals(List.of(RSA384,RSA256),methods(reverse,"SigningMethod"));
            var roleDigest=generate(service,MetadataService.Variant.ALGORITHM_ROLE_DIGEST_384,polling);
            assertEquals(List.of(RSA256),methods(roleDigest,"SigningMethod"));
            assertEquals(List.of(SHA256),methods(roleDigest,"DigestMethod"));
            var sp=role(roleDigest);
            assertEquals(List.of(SHA384),methods(sp,"DigestMethod"));
            assertTrue(methods(sp,"SigningMethod").isEmpty(),"Role digest must not discard entity signing information");
            var roleSigning=generate(service,MetadataService.Variant.ALGORITHM_ROLE_SIGNING_384,polling);
            assertEquals(List.of(SHA256),methods(roleSigning,"DigestMethod"));
            assertEquals(List.of(RSA384),methods(role(roleSigning),"SigningMethod"));
            assertTrue(methods(role(roleSigning),"DigestMethod").isEmpty());
            var absent=generate(service,MetadataService.Variant.ALGORITHM_ABSENT,polling);
            assertEquals(0,absent.getElementsByTagNameNS(MetadataAlgorithmFixtures.ALG,"SigningMethod").getLength());
            assertEquals(0,absent.getElementsByTagNameNS(MetadataAlgorithmFixtures.ALG,"DigestMethod").getLength());
        }
    }
    private Element generate(MetadataService service,MetadataService.Variant variant,boolean polling) {
        assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
        var plan=SamlTestFixtures.idpPlan();
        return SecureXml.parse(polling ? service.generatePolling(plan,variant,"run_alg")
                : service.generate(plan,variant,"run_alg")).getDocumentElement();
    }
    private Element role(Element root) { return (Element)root.getElementsByTagNameNS(MetadataService.MD,"SPSSODescriptor").item(0); }
    private List<String> methods(Element parent,String type) {
        var result=new java.util.ArrayList<String>();
        for(var node=parent.getFirstChild();node!=null;node=node.getNextSibling()) {
            if(!(node instanceof Element ext) || !MetadataService.MD.equals(ext.getNamespaceURI()) || !"Extensions".equals(ext.getLocalName()))continue;
            for(var child=ext.getFirstChild();child!=null;child=child.getNextSibling())
                if(child instanceof Element method && MetadataAlgorithmFixtures.ALG.equals(method.getNamespaceURI()) && type.equals(method.getLocalName()))result.add(method.getAttribute("Algorithm"));
        }
        return List.copyOf(result);
    }
}
