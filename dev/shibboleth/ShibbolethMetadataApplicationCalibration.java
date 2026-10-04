import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.w3c.dom.Element;

/** Public native consumer calibration. No HTTP, IdP configuration, credential, or private-key access. */
public final class ShibbolethMetadataApplicationCalibration {
    static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    static Element role(Element entity) {
        var roles = entity.getElementsByTagNameNS(MD, "SPSSODescriptor");
        ShibbolethMetadataSelectionProducer.require(roles.getLength() == 1);
        return (Element)roles.item(0);
    }
    static Element acs(Element entity, String index) {
        Element selected = null;
        var services = role(entity).getElementsByTagNameNS(MD, "AssertionConsumerService");
        for (int i = 0; i < services.getLength(); i++) {
            var e = (Element)services.item(i);
            if (index.equals(e.getAttribute("index"))) {
                ShibbolethMetadataSelectionProducer.require(selected == null); selected = e;
            }
        }
        ShibbolethMetadataSelectionProducer.require(selected != null); return selected;
    }
    public static void main(String[] args) throws Exception {
        ShibbolethMetadataSelectionProducer.require(args.length == 3);
        var mapper = new ObjectMapper();
        byte[] inputRaw = Files.readAllBytes(Path.of(args[0]));
        JsonNode input = mapper.readTree(inputRaw);
        String mode = input.path("selectedConsumer").asText();
        ShibbolethMetadataSelectionProducer.require("samlscope-native-metadata-application-calibration-input-v1".equals(input.path("schema").asText())
                && "public-native-consumer-calibration-only".equals(input.path("purpose").asText())
                && List.of("stock-native-consumer", "drop-accepted-b-secondary-acs", "retain-conflicting-old-a-acs").contains(mode));
        byte[] stockRaw = Base64.getDecoder().decode(input.path("stockSelectionInputBase64").asText());
        ShibbolethMetadataSelectionProducer.require(ShibbolethMetadataSelectionProducer.sha(stockRaw).equals(input.path("stockSelectionInputSha256").asText()));
        var stock = (ObjectNode)mapper.readTree(stockRaw);
        InitializationService.initialize();
        var parser = XMLObjectProviderRegistrySupport.getParserPool();
        byte[] bRaw = Base64.getDecoder().decode(stock.path("records").get(0).path("metadataBase64").asText());
        byte[] aRaw = Base64.getDecoder().decode(input.path("oldMetadataBase64").asText());
        ShibbolethMetadataSelectionProducer.require(ShibbolethMetadataSelectionProducer.sha(aRaw).equals(input.path("oldMetadataSha256").asText()));
        var b = parser.parse(new ByteArrayInputStream(bRaw));
        var a = parser.parse(new ByteArrayInputStream(aRaw));
        ShibbolethMetadataSelectionProducer.require(b.getDocumentElement().getAttribute("entityID").equals(a.getDocumentElement().getAttribute("entityID")));
        if (mode.equals("drop-accepted-b-secondary-acs")) role(b.getDocumentElement()).removeChild(acs(b.getDocumentElement(), "1"));
        if (mode.equals("retain-conflicting-old-a-acs")) role(b.getDocumentElement()).appendChild(b.importNode(acs(a.getDocumentElement(), "0"), true));
        byte[] consumerRaw = bRaw;
        if (!mode.equals("stock-native-consumer")) {
            var bytes = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(b), new StreamResult(bytes));
            consumerRaw = bytes.toByteArray();
        }
        for (JsonNode row : stock.path("records")) {
            ShibbolethMetadataSelectionProducer.require(Base64.getDecoder().decode(row.path("metadataBase64").asText()).length == bRaw.length
                    && row.path("metadataSha256").asText().equals(ShibbolethMetadataSelectionProducer.sha(bRaw)));
            ((ObjectNode)row).put("metadataBase64", Base64.getEncoder().encodeToString(consumerRaw));
            ((ObjectNode)row).put("metadataSha256", ShibbolethMetadataSelectionProducer.sha(consumerRaw));
        }
        Path nativeInput = Path.of(args[0]).resolveSibling("consumer-" + mode + ".json");
        byte[] nativeRaw = mapper.writeValueAsBytes(stock); Files.write(nativeInput, nativeRaw);
        var captured = new ByteArrayOutputStream(); PrintStream stdout = System.out;
        try {
            System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
            ShibbolethMetadataSelectionProducer.main(new String[]{nativeInput.toString(), args[2]});
        } finally { System.setOut(stdout); }
        var output = mapper.createObjectNode();
        output.put("schema", "samlscope-native-metadata-application-calibration-output-v1");
        output.put("purpose", "public-native-consumer-calibration-only"); output.put("selectedConsumer", mode);
        output.put("counterfactualCalibrationOnly", !mode.equals("stock-native-consumer"));
        output.put("inputSha256", ShibbolethMetadataSelectionProducer.sha(inputRaw));
        output.put("sourceSha256", ShibbolethMetadataSelectionProducer.sha(Files.readAllBytes(Path.of(args[1]))));
        output.put("stockSourceSha256", ShibbolethMetadataSelectionProducer.sha(Files.readAllBytes(Path.of(args[2]))));
        output.put("consumerMetadataBase64", Base64.getEncoder().encodeToString(consumerRaw));
        output.put("consumerMetadataSha256", ShibbolethMetadataSelectionProducer.sha(consumerRaw));
        output.put("consumerInputBase64", Base64.getEncoder().encodeToString(nativeRaw));
        output.put("consumerInputSha256", ShibbolethMetadataSelectionProducer.sha(nativeRaw));
        output.set("nativeOutput", mapper.readTree(captured.toByteArray()));
        output.put("productSettings", 0); output.put("protocolOperations", 0); output.put("credentialPosts", 0);
        output.put("privateKeyRead", false); output.put("controlsAdopted", false);
        System.out.println(mapper.writeValueAsString(output));
    }
}
