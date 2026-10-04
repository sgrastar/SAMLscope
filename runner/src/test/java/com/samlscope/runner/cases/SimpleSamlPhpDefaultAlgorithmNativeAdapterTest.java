package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.store.JsonCodec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SimpleSamlPhpDefaultAlgorithmNativeAdapterTest {
    private static ObjectNode diagnostic() {
        var json=new JsonCodec();var n=json.mapper().createObjectNode();
        n.put("schema","samlscope-ssp-default-consumer-native-api-diagnostic-v1");
        n.putNull("nativeParserValidateAuthnRequest");n.putNull("hostedValidateAuthnRequest");
        n.putNull("nativeParserRedirectValidate");n.putNull("hostedRedirectValidate");
        n.put("configurationWrites",0);n.put("targetHttp",0);n.put("actualProductFinding",false);n.put("actualMd5CryptoVerificationClaimed",false);
        var classes=n.putArray("classes");
        for(var e:java.util.Map.of("SimpleSAML\\Metadata\\SAMLParser","native-parser.php","SimpleSAML\\Module\\saml\\Message","native-message.php",
            "SAML2\\Message","native-legacy-message.php","SAML2\\Utils","native-utils.php","RobRichards\\XMLSecLibs\\XMLSecurityDSig","native-dsig.php",
            "RobRichards\\XMLSecLibs\\XMLSecurityKey","native-key.php").entrySet())classes.addObject().put("class",e.getKey()).put("sha256",SimpleSamlPhpDefaultAlgorithmNativeAdapter.SOURCES.get(e.getValue()));
        return n;
    }
    @Test void stockPublicDiagnosticHasNoProductFindingOrCryptographicMd5Claim() {
        assertDoesNotThrow(()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(diagnostic(),diagnostic()));
    }
    @Test void omittedDefaultAndExplicitValidationSettingsRemainDifferent() {
        for(String key:java.util.List.of("nativeParserValidateAuthnRequest","hostedValidateAuthnRequest",
                "nativeParserRedirectValidate","hostedRedirectValidate")) {
            for(boolean value:new boolean[]{false,true}) {var n=diagnostic();n.put(key,value);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(n,n));}
            var n=diagnostic();n.remove(key);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(n,n));
        }
    }
    @Test void publicApiOutputCannotClaimActualHttpFindingOrMd5Verification() {
        for(String key:java.util.List.of("actualProductFinding","actualMd5CryptoVerificationClaimed")) {
            var n=diagnostic();n.put(key,true);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(n,n));
        }
        for(String key:java.util.List.of("configurationWrites","targetHttp")) {
            var n=diagnostic();n.put(key,1);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(n,n));
        }
    }
    @Test void changedOrAmbiguousLoadedConsumerSourcesFailClosed() {
        var changed=diagnostic();((ObjectNode)changed.path("classes").get(0)).put("sha256","0".repeat(64));
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(changed,changed));
        var duplicate=diagnostic();((com.fasterxml.jackson.databind.node.ArrayNode)duplicate.path("classes")).add(duplicate.path("classes").get(0).deepCopy());
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(duplicate,duplicate));
    }
    @Test void parserApiOutputDoesNotSupplyAnEncryptedIdentifierConsumer() {
        var n=diagnostic();n.put("schema","samlscope-other-decrypt-consumer-v1");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDiagnostic(n,n));
    }
    private static ObjectNode policy() {
        var n=new JsonCodec().mapper().createObjectNode();
        n.putNull("hostedValidateAuthnRequest");n.putNull("hostedRedirectValidate");
        for(String key:java.util.List.of("globalConfigurationSha256","hostedConfigurationSha256","authenticationConfigurationSha256"))n.put(key,"a".repeat(64));
        for(String key:java.util.List.of("autoPrependFile","autoAppendFile","opcachePreload"))n.put(key,"");
        return n;
    }
    @Test void unchangedNativeDefaultRequiresEachOriginalConfigurationIdentity() {
        assertDoesNotThrow(()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDefaultPolicy(policy()));
        for(String key:java.util.List.of("globalConfigurationSha256","hostedConfigurationSha256","authenticationConfigurationSha256")) {
            var n=policy();n.remove(key);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDefaultPolicy(n));
        }
    }
    @Test void emptyDynamicOverrideValueMustBeAnActualString() {
        for(String key:java.util.List.of("autoPrependFile","autoAppendFile","opcachePreload")) {
            var n=policy();n.put(key,"/tmp/foreign.php");assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDefaultPolicy(n));
            n.putNull(key);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDefaultPolicy(n));
            n.put(key,false);assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.validateDefaultPolicy(n));
        }
    }
    private static ObjectNode signatureRow(boolean constructed,String gate) {
        return new JsonCodec().mapper().createObjectNode().put("constructedSignature",constructed).put("nativeSignatureGate",gate);
    }
    @Test void ignoredMd5SignatureWithSuccessfulSsoCannotBecomeAWeakAlgorithmCounterexample() {
        var ignored=SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("md5-digest",signatureRow(false,"SKIPPED"));
        assertEquals(DefaultAlgorithmNativeAdapter.Decision.UNPROVEN,ignored);
        var evidence=java.util.List.of(new EvidenceRef("transcript","tx_same_run_native_original"));
        var observations=java.util.List.of(
            sample("sha256-control",DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS,evidence),
            sample("invalid-sha256-signature",DefaultAlgorithmNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION,evidence),
            sample("md5-digest",ignored,evidence),
            sample("rsa-md5",DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,evidence));
        var outcome=DefaultAlgorithmComparison.evaluate("run_local_original",SimpleSamlPhpDefaultAlgorithmNativeAdapter.ADAPTER,observations,evidence);
        assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());
        assertEquals(java.util.List.of(),outcome.details().get("weak_algorithm_counterexamples"));
        assertFalse(((java.util.List<?>)outcome.details().get("completed_observations")).contains("md5-digest"));
    }
    @Test void skippedOrUnconstructedSignatureCannotProveConsumptionEvenWithAValidationLabel() {
        for(String gate:java.util.List.of("SKIPPED","VALIDATED","REJECTED"))
            assertEquals(DefaultAlgorithmNativeAdapter.Decision.UNPROVEN,
                    SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("md5-digest",signatureRow(false,gate)));
        assertEquals(DefaultAlgorithmNativeAdapter.Decision.UNPROVEN,
                SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("sha256-control",signatureRow(true,"SKIPPED")));
    }
    @Test void actualStrongSignatureValidationRemainsTheSuccessfulControlAndMalformedClaimsFailClosed() {
        assertEquals(DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS,
                SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("sha256-control",signatureRow(true,"VALIDATED")));
        var missing=signatureRow(false,"SKIPPED");missing.remove("constructedSignature");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("md5-digest",missing));
        var textClaim=signatureRow(false,"SKIPPED");textClaim.put("constructedSignature","false");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("md5-digest",textClaim));
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpDefaultAlgorithmNativeAdapter.successfulSignatureDecision("md5-digest",signatureRow(true,"VALIDATED")));
    }
    private static DefaultAlgorithmComparison.Sample sample(String fixture,DefaultAlgorithmNativeAdapter.Decision decision,
            java.util.List<EvidenceRef> evidence) {
        return new DefaultAlgorithmComparison.Sample(fixture,new DefaultAlgorithmNativeAdapter.Use("unchanged-default-policy",
                SimpleSamlPhpDefaultAlgorithmNativeAdapter.CONSUMER,decision,evidence),evidence);
    }
}
