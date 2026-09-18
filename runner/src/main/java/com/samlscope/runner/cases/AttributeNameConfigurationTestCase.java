package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

/** Positive attribute-generation capability, from correlated and cryptographically verified SSO. */
public final class AttributeNameConfigurationTestCase implements TestCase,ConfigurationPrompt,ProtocolEvidenceCase,com.samlscope.runner.EvidenceCampaignCase {
    public static final String ID="IIP-IDP01-a-idp-01";
    static final String URN_NAME="urn:samlscope:test:attribute-name";
    static final String STRING_NAME="SAMLscope arbitrary attribute";
    static final String CUSTOM_FORMAT="urn:samlscope:test:attribute-name-format";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion", P="urn:oasis:names:tc:SAML:2.0:protocol", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final List<String> REQUIRED=List.of("urn-name","non-uri-name","unknown-name-format");
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;
    public AttributeNameConfigurationTestCase(TestCase fallback,TranscriptContentReader content,Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys) {
        this.fallback=Objects.requireNonNull(fallback);this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
        if(!ID.equals(fallback.id()))throw new IllegalArgumentException("Unsupported attribute capability case");
    }
    @Override public String id(){return ID;}
    @Override public TargetRole role(){return TargetRole.IDP;}
    @Override public boolean requiresPreparationConfirmation(){return true;}
    @Override public String instructionEn(){return "Configure the target to emit attributes named '"+URN_NAME+"' and '"+STRING_NAME+"', and use NameFormat '"+CUSTOM_FORMAT+"' on at least one of them. Perform ordinary SSO and confirm the preparation. The Suite verifies the signed output; confirmation alone is not a conformance outcome.";}
    @Override public String evidenceCampaignId(){return "ordinary-sso-transcript";}
    @Override public String evidenceCampaignTitle(){return "Configured attribute generation in ordinary SSO";}
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind(){return com.samlscope.runner.RunCampaignQuery.ActionKind.LOGIN;}
    @Override public CaseStep start(CaseContext context){return fallback.start(context);}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(event instanceof CaseEvent.ConfigConfirmed){
            var observed=observe(context);var details=new LinkedHashMap<String,Object>(observed.details());details.put("configuration_confirmed",true);
            return new CaseStep.Finish(new CaseOutcome(observed.outcome(),observed.notVerifiedReason(),observed.reasonCode(),observed.reasonMessageKey(),observed.evidence(),details));
        }
        return fallback.resume(context,state,event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        var outcome=observe(context);var details=new LinkedHashMap<String,Object>(outcome.details());details.put("configuration_confirmation_required",true);
        return new EvidenceStatus(false,REQUIRED,List.of(),details);
    }
    CaseOutcome observe(CaseContext context){
        var found=new LinkedHashSet<String>();var issues=new ArrayList<String>();var evidence=new LinkedHashSet<EvidenceRef>();
        try {
            if(!context.transcriptComplete())return result(found,List.of("history_incomplete"),evidence);
            var target=SecureXml.parse(metadata.apply(context.runId())).getDocumentElement();
            if(!MD.equals(target.getNamespaceURI()) || !"EntityDescriptor".equals(target.getLocalName()) || target.getAttribute("entityID").isBlank())return result(found,List.of("target_entity_unavailable"),evidence);
            var certificates=MetadataAlgorithmEvidence.signingKeys(target);
            if(certificates.isEmpty())return result(found,List.of("target_signing_keys_unavailable"),evidence);
            var entries=context.transcript().list(context.runId());var ids=new HashSet<String>();
            var requests=new HashMap<String,TranscriptEntry>();var requestXml=new HashMap<String,Element>();var duplicates=new HashSet<String>();
            for(var entry:entries){
                if(!context.runId().equals(entry.runId()) || !ids.add(entry.id()))return result(found,List.of("ambiguous_history"),evidence);
                if(entry.direction()!=Direction.OUTBOUND || !"AuthnRequest".equals(entry.samlSummary().get("type")) || entry.decodedSamlRef()==null)continue;
                var request=SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
                if(!P.equals(request.getNamespaceURI()) || !"AuthnRequest".equals(request.getLocalName()) || request.getAttribute("ID").isBlank())continue;
                if(requests.put(request.getAttribute("ID"),entry)!=null)duplicates.add(request.getAttribute("ID"));
                requestXml.put(entry.id(),request);
            }
            for(var entry:entries){
                if(entry.direction()!=Direction.INBOUND || !"Response".equals(entry.samlSummary().get("type")) || !Boolean.TRUE.equals(entry.samlSummary().get("normalFlowAccepted")))continue;
                var response=SecureXml.parse(content.readDecodedSaml(entry)).getDocumentElement();
                var request=requests.get(response.getAttribute("InResponseTo"));
                if(request==null || duplicates.contains(response.getAttribute("InResponseTo")) || entry.timestamp().isBefore(request.timestamp()))continue;
                var acs=requestXml.get(request.id()).getAttribute("AssertionConsumerServiceURL");
                if(acs.isBlank() || !acs.equals(response.getAttribute("Destination")) || !acs.equals(entry.url())){issues.add("endpoint_unbound");continue;}
                var status=children(response,P,"Status");
                if(status.size()!=1 || children(status.getFirst(),P,"StatusCode").size()!=1 || !"urn:oasis:names:tc:SAML:2.0:status:Success".equals(children(status.getFirst(),P,"StatusCode").getFirst().getAttribute("Value")))continue;
                var signatures=new VerifiedSignatureAlgorithms().read(response,target.getAttribute("entityID"),certificates);
                var plain=children(response,S,"Assertion");
                int expected=children(response,DS,"Signature").size()+plain.stream().mapToInt(a->children(a,DS,"Signature").size()).sum();
                if(signatures.stream().noneMatch(s->"Response".equals(s.element())) || signatures.size()!=expected){issues.add("target_signature_unverified");continue;}
                var assertions=new ArrayList<>(plain);
                for(var wrapper:children(response,S,"EncryptedAssertion")){
                    var key=keys.keyFor(context.runId()).orElseThrow();
                    var assertion=new SamlXmlDecrypter().decrypt(wrapper,key);
                    if(!children(assertion,DS,"Signature").isEmpty()){
                        var doc=SecureXml.newDocument();var envelope=doc.createElementNS(P,"p:Response");doc.appendChild(envelope);envelope.appendChild(doc.importNode(assertion,true));
                        var verified=new VerifiedSignatureAlgorithms().read(envelope,target.getAttribute("entityID"),certificates);
                        if(verified.size()!=1 || !"Assertion".equals(verified.getFirst().element()))throw new IllegalArgumentException("Unverified inner signature");
                    }
                    assertions.add(assertion);
                }
                for(var assertion:assertions){
                    var issuers=children(assertion,S,"Issuer");
                    if(!S.equals(assertion.getNamespaceURI()) || !"Assertion".equals(assertion.getLocalName()) || issuers.size()!=1 || !target.getAttribute("entityID").equals(issuers.getFirst().getTextContent())){issues.add("assertion_issuer_unverified");continue;}
                    for(var statement:children(assertion,S,"AttributeStatement"))for(var attribute:children(statement,S,"Attribute")){
                        String name=attribute.getAttribute("Name");
                        if(URN_NAME.equals(name))found.add("urn-name");
                        if(STRING_NAME.equals(name))found.add("non-uri-name");
                        if((URN_NAME.equals(name)||STRING_NAME.equals(name)) && CUSTOM_FORMAT.equals(attribute.getAttribute("NameFormat")))found.add("unknown-name-format");
                    }
                }
                evidence.add(new EvidenceRef("transcript",request.id()));evidence.add(new EvidenceRef("transcript",entry.id()));
            }
        }catch(Exception unavailable){issues.add("attribute_evidence_unreadable");}
        return result(found,issues,evidence);
    }
    private static CaseOutcome result(Set<String> found,List<String> issues,Set<EvidenceRef> evidence){
        var missing=REQUIRED.stream().filter(v->!found.contains(v)).toList();boolean satisfied=missing.isEmpty()&&issues.isEmpty();
        var code=satisfied?"configuration.attribute-name.capability-observed":"configuration.attribute-name.evidence-incomplete";
        return new CaseOutcome(satisfied?Outcome.SATISFIED:Outcome.NOT_VERIFIED,satisfied?null:"attribute_name_evidence_incomplete",code,code,List.copyOf(evidence),Map.of("required_variants",REQUIRED,"observed_variants",List.copyOf(found),"missing_variants",missing,"evidence_issues",List.copyOf(issues)));
    }
}
