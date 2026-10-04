package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import static com.samlscope.runner.cases.ShibbolethMetadataApplicationEvidence.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The SOAP transport error is conclusive only with its unique request-bound native signature cause. */
class ShibbolethMetadataApplicationSourceTest {
    static final String ENTITY = "urn:samlscope:test:peer";
    static final String ACTION = "action_0123456789abcdef";
    static final Instant BEFORE = Instant.parse("2026-10-03T12:00:00Z");
    static final Instant AFTER = BEFORE.plusSeconds(1);
    static final String AUDIT = "SAMLscope-application-v1|_" + ACTION + "|||" + ENTITY
            + "|||true|SOAP||" + ECP_PROFILE + "|2026-10-03T12:00:00.3Z";
    static final String VALIDATION = "2026-10-03 12:00:00,100 - WARN SAMLProtocolMessageXMLSignatureSecurityHandler - "
            + "Validation of protocol message signature failed for context issuer '" + ENTITY
            + "', message type: {" + P + "}AuthnRequest";
    static final String ERROR = "2026-10-03 12:00:00,200 - WARN org.opensaml.profile.action.impl.LogEvent - "
            + "A non-proceed event occurred while processing the request: MessageAuthenticationError";
    final JsonCodec codec = new JsonCodec();

    ObjectNode projection() throws Exception {
        ObjectNode p = codec.mapper().createObjectNode();
        p.put("schema", "samlscope-shibboleth-metadata-application-public-causes-v1");
        p.put("privateLogPersisted", false);
        p.put("sourcePath", "/opt/reference-idp/logs/idp-process.log");
        p.put("sourcePrefixBytes", 1000);
        p.put("sourcePrefixSha256", "a".repeat(64));
        p.put("sourcePrefixRecheckedSha256", "a".repeat(64));
        ObjectNode op = p.putArray("operations").addObject();
        op.put("fixture", "fixture-test"); op.put("actionId", ACTION);
        op.put("requestReference", "tx_request"); op.put("responseReference", "tx_response");
        op.put("requestSha256", "b".repeat(64)); op.put("responseSha256", "c".repeat(64));
        ObjectNode sequence = op.putObject("nativeEventSequence");
        sequence.put("auditLineNumber", 30); sequence.putArray("validationLineNumbers").add(10);
        sequence.putArray("errorLineNumbers").add(20);
        var lines = p.putArray("publicCandidateLines");
        for (var row : List.of(List.of("native-signature-validation-failure", VALIDATION, "10", "2026-10-03T12:00:00.1Z"),
                List.of("native-message-authentication-error", ERROR, "20", "2026-10-03T12:00:00.2Z"),
                List.of("native-peer-audit", AUDIT, "30", "2026-10-03T12:00:00.3Z"))) {
            ObjectNode line = lines.addObject(); line.put("kind", row.get(0)); line.put("raw", row.get(1));
            line.put("lineSha256", hash(row.get(1).getBytes(StandardCharsets.UTF_8)));
            line.put("lineNumber", Integer.parseInt(row.get(2))); line.put("nativeLoggedAt", row.get(3));
        }
        return p;
    }
    void verify(ObjectNode p) throws Exception {
        ShibbolethMetadataApplicationSource.validatePaosCause(p, "fixture-test", ACTION, "tx_request", "tx_response",
                "b".repeat(64), "c".repeat(64), ENTITY, BEFORE, AFTER, AUDIT);
    }
    @Test void originalRequestAndUnambiguousNativeSignatureCauseVerify() throws Exception {
        assertDoesNotThrow(() -> verify(projection()));
    }
    @Test void genericSoapFaultWithoutNativeCauseCannotDetermineTargetFailure() throws Exception {
        ObjectNode p = projection(); p.putArray("publicCandidateLines");
        assertThrows(Unproven.class, () -> verify(p));
    }
    @Test void anotherRequestWithTheSameErrorCannotSatisfyThisRequest() throws Exception {
        ObjectNode p = projection(); ((ObjectNode)p.path("operations").get(0)).put("actionId", "action_other");
        assertThrows(Unproven.class, () -> verify(p));
    }
    @Test void recomputedForeignIssuerLineIsRejected() throws Exception {
        ObjectNode p = projection(); ObjectNode line = (ObjectNode)p.path("publicCandidateLines").get(0);
        String raw = VALIDATION.replace(ENTITY, "urn:other:peer");
        line.put("raw", raw); line.put("lineSha256", hash(raw.getBytes(StandardCharsets.UTF_8)));
        assertThrows(Unproven.class, () -> verify(p));
    }
    @Test void OutOfEpochNativeCauseIsNotCorrelatedByTimestampProximity() throws Exception {
        ObjectNode p = projection(); ((ObjectNode)p.path("publicCandidateLines").get(0)).put("nativeLoggedAt", BEFORE.minusSeconds(1).toString());
        assertThrows(Unproven.class, () -> verify(p));
    }
    @Test void AdditionalValidationCandidateMakesTheCausalSequenceAmbiguous() throws Exception {
        ObjectNode p = projection(); var lines = p.putArray("publicCandidateLines");
        ObjectNode duplicate = (ObjectNode)projection().path("publicCandidateLines").get(0).deepCopy();
        duplicate.put("lineNumber", 11);
        var original = projection().path("publicCandidateLines");
        lines.add(original.get(0)); lines.add(duplicate); lines.add(original.get(1)); lines.add(original.get(2));
        assertThrows(Unproven.class, () -> verify(p));
    }
    @Test void ChangedNativePrefixCannotBeUsedAsTheSameOriginal() throws Exception {
        ObjectNode p = projection(); p.put("sourcePrefixRecheckedSha256", "d".repeat(64));
        assertThrows(Unproven.class, () -> verify(p));
    }
    @Test void endpointRefusalAndSignatureRefusalHaveDistinctVisibleEvidence() {
        byte[] endpoint = "<h1>Unable to Respond</h1>".getBytes(StandardCharsets.UTF_8);
        byte[] signature = "<h1>Message Security Error</h1>".getBytes(StandardCharsets.UTF_8);
        assertTrue(visibleError(endpoint, "EndpointResolutionFailed"));
        assertFalse(visibleError(endpoint, "MessageAuthenticationError"));
        assertTrue(visibleError(signature, "MessageAuthenticationError"));
        assertFalse(visibleError(signature, "EndpointResolutionFailed"));
        assertFalse(visibleError("<script>Message Security Error</script>".getBytes(StandardCharsets.UTF_8), "MessageAuthenticationError"));
    }
    org.w3c.dom.Element metadata(String variant) {
        return xml(("<md:EntityDescriptor xmlns:md='"+MD+"' entityID='"+ENTITY+"'><md:SPSSODescriptor protocolSupportEnumeration='"+P+"'><md:KeyDescriptor use='signing'/><md:AssertionConsumerService Binding='"+POST+"' Location='https://peer.example/"+variant+"/0' index='0'/><md:AssertionConsumerService Binding='"+POST+"' Location='https://peer.example/"+variant+"/1' index='1'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8));
    }
    org.w3c.dom.Element omitted() {
        var b=metadata("b");role(b).removeChild(com.samlscope.runner.cases.MetadataAlgorithmEvidence.children(role(b),MD,"AssertionConsumerService").getLast());return b;
    }
    org.w3c.dom.Element retained() {
        var b=metadata("b");var a=metadata("a");role(b).appendChild(b.getOwnerDocument().importNode(com.samlscope.runner.cases.MetadataAlgorithmEvidence.children(role(a),MD,"AssertionConsumerService").getFirst(),true));return b;
    }
    @Test void acceptedSecondaryAcsOmissionChangesOnlyTheApprovedApplicationAxis() {
        assertDoesNotThrow(()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),metadata("a"),omitted(),"drop-accepted-b-secondary-acs"));
    }
    @Test void conflictingOldAcsRetentionChangesOnlyTheApprovedReplacementAxis() {
        assertDoesNotThrow(()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),metadata("a"),retained(),"retain-conflicting-old-a-acs"));
    }
    @Test void calibrationLabelAloneDoesNotProveConsumerMutation() {
        assertThrows(Unproven.class,()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),metadata("a"),metadata("b"),"drop-accepted-b-secondary-acs"));
    }
    @Test void swappingTheApprovedTriggerCannotReuseTheOtherProducerOutput() {
        assertThrows(Unproven.class,()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),metadata("a"),omitted(),"retain-conflicting-old-a-acs"));
    }
    @Test void unrelatedSigningPurposeChangeIsNotAnEndpointOnlyCalibration() {
        var changed=omitted();com.samlscope.runner.cases.MetadataAlgorithmEvidence.children(role(changed),MD,"KeyDescriptor").getFirst().setAttribute("use","encryption");
        assertThrows(Unproven.class,()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),metadata("a"),changed,"drop-accepted-b-secondary-acs"));
    }
    @Test void oldEndpointsFromAnotherEntityDoNotQualifyAsSameEntityReplacement() {
        var foreign=metadata("a");foreign.setAttribute("entityID","urn:another:peer");
        assertThrows(Unproven.class,()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),foreign,retained(),"retain-conflicting-old-a-acs"));
    }
    @Test void unapprovedConsumerBehaviorCannotInventAnotherCalibrationBranch() {
        assertThrows(Unproven.class,()->ShibbolethMetadataApplicationSource.validateConsumerMutation(metadata("b"),metadata("a"),metadata("b"),"accept-all-keys"));
    }
}
