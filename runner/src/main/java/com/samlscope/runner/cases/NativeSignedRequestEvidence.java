package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Replays original outbox fixtures and request-bound native audit events. Never infers rejection from silence. */
public final class NativeSignedRequestEvidence implements Function<CaseContext, Optional<CaseOutcome>> {
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final Set<Fixture> REQUIRED=Set.of(Fixture.VALID,Fixture.TAMPERED_ACS,Fixture.BAD_REFERENCE,Fixture.BAD_SIGNATURE_VALUE);
    private final String caseId;
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final Function<String,IdpErrorProbeConfiguration> configurations;
    private final SamlPlanCredentialsProvider keys;

    public NativeSignedRequestEvidence(String caseId,Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,Function<String,IdpErrorProbeConfiguration> configurations,SamlPlanCredentialsProvider keys) {
        if(!supports(caseId))throw new IllegalArgumentException("Unsupported native algorithm case");
        this.caseId=caseId;this.directory=directory.toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.configurations=Objects.requireNonNull(configurations);this.keys=Objects.requireNonNull(keys);
    }
    public static boolean supports(String id) {
        return Set.of(IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE,IdpSignedRequestScenarioTestCase.RSA_SHA256_CASE).contains(id);
    }
    @Override public Optional<CaseOutcome> apply(CaseContext context) {
        String stage="receipt-unavailable";
        try {
            require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var file=directory.resolve(context.runId()+"-"+caseId+".json");
            if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return Optional.empty();
            require(context.transcriptComplete() && Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) && Files.size(file)<=1048576);
            var rawReceipt=Files.readAllBytes(file);var receipt=new JsonCodec().mapper().readTree(rawReceipt);
            require("samlscope-native-signed-request-v1".equals(receipt.path("schema").asText())
                && caseId.equals(receipt.path("caseId").asText()) && context.runId().equals(receipt.path("runId").asText()));
            String adapter=receipt.path("evidenceAdapter").asText("shibboleth-audit");
            require(Set.of("shibboleth-audit","simplesamlphp-native-http","keycloak-native-event").contains(adapter));
            boolean nativeHttp="simplesamlphp-native-http".equals(adapter);
            boolean nativeKeycloak="keycloak-native-event".equals(adapter);
            boolean shibboleth="shibboleth-audit".equals(adapter);
            var targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(receipt.path("targetMetadataSha256").asText()));
            var target=SecureXml.parse(targetRaw).getDocumentElement();var certificates=MetadataAlgorithmEvidence.signingKeys(target);
            require(!certificates.isEmpty());var config=configurations.apply(context.runId());require(config.preconditionsSatisfied());
            var credentials=keys.credentialsFor(context.runId()).orElseThrow();
            require("RSA".equals(credentials.certificate().getPublicKey().getAlgorithm()));
            var entries=new HashMap<String,TranscriptEntry>();
            for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId()) && entries.put(e.id(),e)==null);
            var originals=new HashMap<String,byte[]>();
            stage="originals-unproven";
            for(var item:receipt.path("rawEvidence")) {
                var e=entries.get(item.path("reference").asText());require(e!=null);
                var bytes=content.readDecodedSaml(e);require(hash(bytes).equals(item.path("sha256").asText()) && originals.put(e.id(),bytes)==null);
            }
            require(receipt.path("exchanges").isArray() && receipt.path("exchanges").size()==REQUIRED.size());
            var collected=Instant.parse(receipt.path("collectedAt").asText());
            var fixtures=new HashSet<Fixture>();var requestIds=new HashSet<String>();var evidence=new LinkedHashSet<EvidenceRef>();
            for(var item:receipt.path("exchanges")) {
                var fixture=Fixture.valueOf(item.path("fixture").asText());require(REQUIRED.contains(fixture) && fixtures.add(fixture));
                stage="fixture-unproven:"+fixture.name();
                var sent=entries.get(item.path("requestReference").asText());require(sent!=null && sent.direction()==Direction.OUTBOUND);
                require("AuthnRequest".equals(sent.samlSummary().get("type")) && originals.containsKey(sent.id()));
                var raw=originals.get(sent.id());var request=SecureXml.parse(raw).getDocumentElement();
                require(P.equals(request.getNamespaceURI()) && "AuthnRequest".equals(request.getLocalName()));
                var id=request.getAttribute("ID");require(!id.isBlank() && requestIds.add(id));
                require(Boolean.TRUE.equals(sent.samlSummary().get("active_probe")) && caseId.equals(sent.samlSummary().get("scenario_case_id"))
                    && fixture.name().toLowerCase(Locale.ROOT).replace('_','-').equals(sent.samlSummary().get("fixture_id"))
                    && id.equals("_"+sent.samlSummary().get("action_id")) && sent.correlationId().equals(sent.samlSummary().get("action_id")));
                require(entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND && Objects.equals(sent.correlationId(),e.correlationId())).count()==1);
                require(config.ssoEndpoint().toString().equals(sent.url()) && config.ssoEndpoint().toString().equals(request.getAttribute("Destination")));
                // Rebuilding with the Run's immutable signing key proves the exact intended mutation,
                // including a valid signature before ACS tampering and the original signed reference.
                var expected=new SamlSignedRequestFactory().build(fixture,id,config.ssoEndpoint(),config.suiteIssuer(),
                    config.registeredAcs(),Instant.parse(request.getAttribute("IssueInstant")),credentials);
                require(Arrays.equals(expected,raw));
                var audit=item.path("audit");stage="native-event-unproven:"+fixture.name();
                if(shibboleth) {
                    require(id.equals(audit.path("request_id").asText()) && config.suiteIssuer().equals(audit.path("sp").asText()));
                    require("true".equals(audit.path("signed_inbound").asText()) && "POST".equals(audit.path("binding").asText())
                        && "http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(audit.path("profile").asText()));
                    var time=Instant.parse(audit.path("timestamp").asText());require(!time.isBefore(sent.timestamp()) && !time.isAfter(collected));
                }
                var responses=new ArrayList<TranscriptEntry>();
                for(var e:entries.values())if(e.direction()==Direction.INBOUND && "Response".equals(e.samlSummary().get("type"))) {
                    var xml=SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement();
                    if(id.equals(xml.getAttribute("InResponseTo")))responses.add(e);
                }
                evidence.add(new EvidenceRef("transcript",sent.id()));
                if(fixture!=Fixture.VALID) {
                    if(nativeHttp) {
                        var http=item.path("nativeHttp");
                        require(id.equals(http.path("request_id").asText()) && hash(raw).equals(http.path("request_sha256").asText()));
                        require(sent.url().equals(http.path("request_url").asText()) && sent.url().equals(http.path("response_url").asText()));
                        require(http.path("response_status").asInt()==500 && !http.path("saml_response_form_present").asBoolean(true));
                        require(http.path("response_body_sha256").asText().matches("[0-9a-f]{64}"));
                        String expectedError=fixture==Fixture.BAD_SIGNATURE_VALUE?"signature-value-invalid":"signature-not-established";
                        require(expectedError.equals(http.path("native_signature_rejection").asText()));
                        var time=Instant.parse(http.path("observed_at").asText());require(!time.isBefore(sent.timestamp()) && !time.isAfter(collected));
                    } else if(nativeKeycloak) {
                        var event=item.path("nativeEvent");var http=item.path("nativeHttp");
                        require(id.equals(event.path("request_id").asText()) && hash(raw).equals(event.path("request_sha256").asText())
                            && config.suiteIssuer().equals(event.path("issuer").asText()));
                        require("LOGIN_ERROR".equals(event.path("event_type").asText()) && "invalid_signature".equals(event.path("error").asText()));
                        require(id.equals(http.path("request_id").asText()) && hash(raw).equals(http.path("request_sha256").asText()));
                        require(sent.url().equals(http.path("request_url").asText()) && sent.url().equals(http.path("response_url").asText())
                            && http.path("response_url_exact_match").asBoolean(false));
                        require(http.path("response_status").asInt()==400 && !http.path("saml_response_form_present").asBoolean(true));
                        require(http.path("response_body_sha256").asText().matches("[0-9a-f]{64}"));
                        var start=Instant.parse(http.path("started_at").asText());var finish=Instant.parse(http.path("finished_at").asText());
                        var time=Instant.parse(event.path("observed_at").asText());
                        var emitted=Instant.ofEpochMilli(event.path("event_time").asLong(-1));
                        require(!start.isBefore(sent.timestamp()) && !finish.isAfter(collected) && !finish.isBefore(start));
                        require(!time.isBefore(start) && !time.isAfter(finish) && !emitted.isBefore(start) && !emitted.isAfter(time));
                    } else require("MessageAuthenticationError".equals(audit.path("event").asText()) && audit.path("status").asText().isEmpty());
                    require(responses.isEmpty());
                    continue;
                }
                if(shibboleth)require(audit.path("event").asText().isEmpty() && "Success".equals(audit.path("status").asText()));
                if(nativeKeycloak)require(item.path("nativeEvent").isMissingNode() || item.path("nativeEvent").isNull());
                require(responses.size()==1 && responses.getFirst().id().equals(item.path("responseReference").asText()));
                var received=responses.getFirst();require(originals.containsKey(received.id()) && received.timestamp().isAfter(sent.timestamp()));
                var response=SecureXml.parse(originals.get(received.id())).getDocumentElement();
                require(config.registeredAcs().toString().equals(received.url()) && received.url().equals(response.getAttribute("Destination")));
                require(children(response,S,"Assertion").size()+children(response,S,"EncryptedAssertion").size()==1);
                var statuses=children(response,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");
                require(codes.size()==1 && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(codes.getFirst().getAttribute("Value")));
                stage="producer-signature-unproven";
                var signatures=new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),certificates);
                require(signatures.stream().anyMatch(s->"Response".equals(s.element()) &&
                    (caseId.equals(IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE)
                        ? "http://www.w3.org/2001/04/xmlenc#sha256".equals(s.digestAlgorithm())
                        : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".equals(s.signatureAlgorithm()))));
                evidence.add(new EvidenceRef("transcript",received.id()));
            }
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"algorithm.native-verification-observed","algorithm.native-verification-observed",
                List.copyOf(evidence),Map.of("native_receipt_sha256",hash(rawReceipt),"preparation_source","local-native-adapter","evidence_adapter",adapter,
                    "producer_signature_verified",true,"original_fixture_replay_verified",true,
                    "completed_observations",REQUIRED.stream().map(Enum::name).sorted().toList())));
        } catch(Exception unavailable) {
            return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_signature_evidence_unproven",
                "algorithm.native-evidence-incomplete","algorithm.native-evidence-incomplete",List.of(),Map.of("evidence_issue",stage)));
        }
    }
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Unproven native signature evidence");}
}
