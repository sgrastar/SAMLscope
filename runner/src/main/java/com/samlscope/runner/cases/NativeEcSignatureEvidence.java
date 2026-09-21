package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;

/** Local native-adapter audit evidence supplements a protocol control, never a silence-based rejection. */
public final class NativeEcSignatureEvidence implements Function<CaseContext, Optional<CaseOutcome>> {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    public NativeEcSignatureEvidence(Path directory, TranscriptContentReader content, Function<String,byte[]> metadata) {
        this.directory=directory.toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
    }
    @Override public Optional<CaseOutcome> apply(CaseContext context) {
        try {
            require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var file=directory.resolve(context.runId()+".json");
            if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return Optional.empty();
            require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) && Files.size(file)<=1048576 && context.transcriptComplete());
            var receipt=new JsonCodec().mapper().readTree(Files.readAllBytes(file));
            require("samlscope-native-ec-signature-v1".equals(receipt.path("schema").asText()) && context.runId().equals(receipt.path("runId").asText()));
            String adapter=receipt.path("evidenceAdapter").asText("shibboleth-audit");
            require(Set.of("shibboleth-audit","simplesamlphp-native-http","keycloak-native-event").contains(adapter));
            boolean shibboleth="shibboleth-audit".equals(adapter), keycloak="keycloak-native-event".equals(adapter);
            var targetRaw=metadata.apply(context.runId());require(hash(targetRaw).equals(receipt.path("targetMetadataSha256").asText()));
            var target=SecureXml.parse(targetRaw).getDocumentElement();var targetKeys=MetadataAlgorithmEvidence.signingKeys(target);
            require(!targetKeys.isEmpty());
            var entries=new HashMap<String,TranscriptEntry>();
            for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId()) && entries.put(entry.id(),entry)==null);
            var originals=new HashMap<String,Element>();
            for(var item:receipt.path("rawEvidence")) {
                String ref=item.path("reference").asText();var entry=entries.get(ref);require(entry!=null);
                var raw=content.readDecodedSaml(entry);require(hash(raw).equals(item.path("sha256").asText()));
                require(originals.put(ref,SecureXml.parse(raw).getDocumentElement())==null);
            }
            var evidence=new LinkedHashSet<EvidenceRef>();var seen=new HashSet<String>();var requests=new HashSet<String>();
            String ecKey=null,spEntity=null;boolean validEcRejected=false;
            require(receipt.path("exchanges").isArray() && receipt.path("exchanges").size()==3);
            Instant collected=Instant.parse(receipt.path("collectedAt").asText());
            for(var item:receipt.path("exchanges")) {
                String variant=item.path("variant").asText();
                require(Set.of("control","ecdsa-sha256","ecdsa-sha256-invalid-signature").contains(variant) && seen.add(variant));
                boolean invalid=variant.equals("ecdsa-sha256-invalid-signature"), rsa=variant.equals("control");
                var prepared=entries.get(item.path("metadataReference").asText());var sent=entries.get(item.path("requestReference").asText());
                require(prepared!=null && sent!=null && prepared.direction()==Direction.OUTBOUND && sent.direction()==Direction.OUTBOUND);
                require("MetadataPrepared".equals(prepared.samlSummary().get("type")) && "AuthnRequest".equals(sent.samlSummary().get("type")));
                require(variant.equals(prepared.samlSummary().get("variant")) && variant.equals(sent.samlSummary().get("variant")));
                require(!MetadataProbeCorrelation.signatureControl(sent) && prepared.timestamp().isBefore(sent.timestamp()));
                var fetch=entries.get(String.valueOf(prepared.samlSummary().get("fetchTranscriptId")));
                require(fetch!=null && fetch.direction()==Direction.INBOUND && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                    && variant.equals(fetch.samlSummary().get("variant")) && !fetch.timestamp().isAfter(prepared.timestamp()));
                var sp=originals.get(prepared.id());var request=originals.get(sent.id());require(sp!=null && request!=null);
                require(MD.equals(sp.getNamespaceURI()) && "EntityDescriptor".equals(sp.getLocalName()));
                require(hash(content.readDecodedSaml(prepared)).equals(prepared.samlSummary().get("metadataSha256")));
                require(P.equals(request.getNamespaceURI()) && "AuthnRequest".equals(request.getLocalName()));
                String requestId=request.getAttribute("ID");require(!requestId.isBlank() && requests.add(requestId) && requestId.equals(sent.samlSummary().get("id")));
                require(entries.values().stream().filter(e->e.direction()==Direction.OUTBOUND && requestId.equals(e.samlSummary().get("id"))).count()==1);
                var issuers=children(request,S,"Issuer");require(issuers.size()==1 && sp.getAttribute("entityID").equals(issuers.getFirst().getTextContent()));
                if(spEntity==null)spEntity=sp.getAttribute("entityID");else require(spEntity.equals(sp.getAttribute("entityID")));
                require(request.getAttribute("Destination").equals(sent.url()) && children(target,MD,"IDPSSODescriptor").stream()
                    .flatMap(role->children(role,MD,"SingleSignOnService").stream()).anyMatch(e->sent.url().equals(e.getAttribute("Location"))));
                var roles=children(sp,MD,"SPSSODescriptor");require(roles.size()==1);
                String acs=request.getAttribute("AssertionConsumerServiceURL");
                require(children(roles.getFirst(),MD,"AssertionConsumerService").stream().anyMatch(e->acs.equals(e.getAttribute("Location"))));
                var certs=new ArrayList<X509Certificate>();
                for(var key:children(roles.getFirst(),MD,"KeyDescriptor")) {
                    if(!key.getAttribute("use").isBlank() && !key.getAttribute("use").equals("signing"))continue;
                    for(var info:children(key,DS,"KeyInfo"))for(var data:children(info,DS,"X509Data"))for(var cert:children(data,DS,"X509Certificate"))
                        certs.add((X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(cert.getTextContent()))));
                }
                require(certs.size()==1 && certs.getFirst().getPublicKey().getAlgorithm().equals(rsa?"RSA":"EC"));
                if(!rsa) {String key=hash(certs.getFirst().getPublicKey().getEncoded());if(ecKey==null)ecKey=key;else require(ecKey.equals(key));}
                var signatures=children(request,DS,"Signature");require(signatures.size()==1);
                var infos=children(signatures.getFirst(),DS,"SignedInfo");require(infos.size()==1);
                var methods=children(infos.getFirst(),DS,"SignatureMethod");require(methods.size()==1 && ("http://www.w3.org/2001/04/xmldsig-more#"+(rsa?"rsa":"ecdsa")+"-sha256").equals(methods.getFirst().getAttribute("Algorithm")));
                request.setIdAttribute("ID",true);
                require(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(request));
                require(new XmlSignatureVerifier().hasValidEnvelopedSignature(request,certs.getFirst())!=invalid);
                var audit=item.path("audit");
                if(shibboleth) {
                    require(requestId.equals(audit.path("request_id").asText()) && spEntity.equals(audit.path("sp").asText()));
                    require("true".equals(audit.path("signed_inbound").asText()) && "POST".equals(audit.path("binding").asText())
                        && "http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(audit.path("profile").asText()));
                    var time=Instant.parse(audit.path("timestamp").asText());require(!time.isBefore(sent.timestamp()) && !time.isAfter(collected));
                }
                var responses=new ArrayList<TranscriptEntry>();
                for(var e:entries.values()) if(e.direction()==Direction.INBOUND && "Response".equals(e.samlSummary().get("type"))) {
                    var xml=SecureXml.parse(content.readDecodedSaml(e)).getDocumentElement();if(requestId.equals(xml.getAttribute("InResponseTo")))responses.add(e);
                }
                if(invalid || (!rsa && responses.isEmpty())) {
                    if(shibboleth)require("MessageAuthenticationError".equals(audit.path("event").asText()) && audit.path("status").asText().isEmpty());
                    else {
                        var http=item.path("nativeHttp");String requestHash=hash(content.readDecodedSaml(sent));
                        require(requestId.equals(http.path("request_id").asText()) && requestHash.equals(http.path("request_sha256").asText()));
                        require(sent.url().equals(http.path("request_url").asText()) && sent.url().equals(http.path("response_url").asText()));
                        require(!http.path("saml_response_form_present").asBoolean(true) && http.path("response_body_sha256").asText().matches("[0-9a-f]{64}"));
                        if(keycloak) {
                            var event=item.path("nativeEvent");
                            require(requestId.equals(event.path("request_id").asText()) && requestHash.equals(event.path("request_sha256").asText())
                                && spEntity.equals(event.path("issuer").asText()));
                            require("LOGIN_ERROR".equals(event.path("event_type").asText()) && "invalid_signature".equals(event.path("error").asText()));
                            require(http.path("response_status").asInt()==400 && http.path("response_url_exact_match").asBoolean(false));
                            var start=Instant.parse(http.path("started_at").asText());var finish=Instant.parse(http.path("finished_at").asText());
                            var observed=Instant.parse(event.path("observed_at").asText());var emitted=Instant.ofEpochMilli(event.path("event_time").asLong(-1));
                            require(!start.isBefore(sent.timestamp()) && !finish.isAfter(collected) && !finish.isBefore(start));
                            require(!observed.isBefore(start) && !observed.isAfter(finish) && !emitted.isBefore(start) && !emitted.isAfter(observed));
                        } else {
                            require(http.path("response_status").asInt()==500 && "signature-value-invalid".equals(http.path("native_signature_rejection").asText()));
                            var observed=Instant.parse(http.path("observed_at").asText());
                            require(!observed.isBefore(sent.timestamp()) && !observed.isAfter(collected));
                        }
                    }
                    require(responses.isEmpty()); // A native rejection is required; a conflicting callback prevents adoption.
                    if(!invalid)validEcRejected=true;
                } else {
                    if(shibboleth)require(audit.path("event").asText().isEmpty() && "Success".equals(audit.path("status").asText()));
                    if(keycloak)require(item.path("nativeEvent").isMissingNode() || item.path("nativeEvent").isNull());
                    require(responses.size()==1 && responses.getFirst().id().equals(item.path("responseReference").asText()));
                    var received=responses.getFirst();var response=originals.get(received.id());require(response!=null && received.timestamp().isAfter(sent.timestamp()));
                    require(acs.equals(response.getAttribute("Destination")) && acs.equals(received.url()));
                    var statuses=children(response,P,"Status");require(statuses.size()==1);var codes=children(statuses.getFirst(),P,"StatusCode");
                    require(codes.size()==1 && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(codes.getFirst().getAttribute("Value")));
                    require(children(response,S,"Assertion").size()+children(response,S,"EncryptedAssertion").size()==1);
                    require(new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),targetKeys).stream().anyMatch(a->"Response".equals(a.element())));
                    evidence.add(new EvidenceRef("transcript",received.id()));
                }
                for(var entry:List.of(fetch,prepared,sent))evidence.add(new EvidenceRef("transcript",entry.id()));
            }
            // Rejecting a valid request is an observation, not proof that no configuration supports EC.
            return Optional.of(new CaseOutcome(validEcRejected?Outcome.NOT_VERIFIED:Outcome.SATISFIED,
                validEcRejected?"valid_ec_request_rejected_support_unproven":null,
                validEcRejected?"ec-signature.native-valid-request-rejected":"ec-signature.native-support-observed",
                validEcRejected?"ec-signature.incomplete":"ec-signature.support-observed",
                List.copyOf(evidence),Map.of("preparation_source","local-native-adapter","native_receipt_sha256",hash(Files.readAllBytes(file)),
                    "negative_control","request-bound-native-authentication-error","original_signatures_verified",true,
                    "evidence_adapter",adapter,"valid_ec_request_rejected",validEcRejected)));
        } catch(Exception unproven) {
            return Optional.of(CaseOutcome.notVerified("native_ec_signature_evidence_unproven","ec-signature.native-incomplete"));
        }
    }
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Unproven native EC signature evidence");}
}
