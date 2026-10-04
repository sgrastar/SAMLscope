import java.net.URI;
import java.math.BigInteger;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.impl.SignatureAlgorithmValidator;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SamlDefaultAlgorithmFixtures;
import com.samlscope.saml.normal.SecureXml;

/** Host-only synthetic keys. Tests the actual producer predicate without native private inputs. */
public final class DefaultAlgorithmCalibrationHostPreflight {
    static void require(boolean value,String reason){if(!value)throw new IllegalStateException(reason);}
    public static void main(String[] args)throws Exception {
        Security.addProvider(new BouncyCastleProvider());InitializationService.initialize();var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();Instant at=Instant.parse("2026-10-03T15:00:00Z");
        var name=new X500Name("CN=public-synthetic-host-control");var certificate=new JcaX509CertificateConverter().setProvider("BC").getCertificate(new JcaX509v3CertificateBuilder(name,BigInteger.ONE,Date.from(at.minusSeconds(60)),Date.from(at.plusSeconds(600)),name,pair.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate())));
        var credentials=new PlanCredentials(pair.getPrivate(),certificate);var stock=DefaultSecurityConfigurationBootstrap.buildDefaultSignatureValidationConfiguration();var excluded=new TreeSet<>(stock.getExcludedAlgorithms());
        var relaxed=new TreeSet<>(excluded);relaxed.removeAll(Set.of(ShibbolethDefaultAlgorithmCalibration.MD5,ShibbolethDefaultAlgorithmCalibration.RSA_MD5,ShibbolethDefaultAlgorithmCalibration.HMAC_MD5));
        var helper=new SamlDefaultAlgorithmFixtures();int checks=0;
        for(var fixture:SamlDefaultAlgorithmFixtures.Fixture.values()) {
            byte[] raw=helper.authnRequest(fixture,"_same-public-input",URI.create("https://idp.example/sso"),"https://suite.example/sp",URI.create("https://suite.example/acs"),at,credentials);String hash=ShibbolethDefaultAlgorithmCalibration.sha(raw);
            var root=SecureXml.parse(raw).getDocumentElement();var normal=ShibbolethDefaultAlgorithmCalibration.signatureDecision(root,certificate,new SignatureAlgorithmValidator(stock.getIncludedAlgorithms(),excluded));
            var mutant=ShibbolethDefaultAlgorithmCalibration.signatureDecision(root,certificate,new SignatureAlgorithmValidator(stock.getIncludedAlgorithms(),relaxed));
            boolean math=fixture!=SamlDefaultAlgorithmFixtures.Fixture.INVALID_SHA256_SIGNATURE,stockAllowed=fixture==SamlDefaultAlgorithmFixtures.Fixture.SHA256_CONTROL||fixture==SamlDefaultAlgorithmFixtures.Fixture.INVALID_SHA256_SIGNATURE;
            require(normal.mathematicalValid()==math&&normal.allowed()==stockAllowed,fixture+" stock decision wrong");checks++;
            require(mutant.mathematicalValid()==math&&mutant.allowed(),fixture+" selected mutant wrong");checks++;
            require(ShibbolethDefaultAlgorithmCalibration.sha(raw).equals(hash),"Input bytes changed");checks++;
            root.setAttribute("AssertionConsumerServiceURL","https://foreign.example/acs");var tampered=ShibbolethDefaultAlgorithmCalibration.signatureDecision(root,certificate,new SignatureAlgorithmValidator(stock.getIncludedAlgorithms(),relaxed));require(!tampered.mathematicalValid(),fixture+" tampered input accepted");checks++;
        }
        System.out.println("{\"hostOnly\":true,\"syntheticKeysOnly\":true,\"privateKeysExported\":false,\"checks\":"+checks+",\"nativeOperations\":0}");
    }
}
