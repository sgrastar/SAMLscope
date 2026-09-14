package com.samlscope.runner.cases;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;

/** SP-initiated synchronous SLO. Session termination and response status branching belong to other cases. */
public final class IdpBasicLogoutScenarioTestCase implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String ID = "IIP-IDP17-a-idp-01";
    public static final String REDIRECT_ID = "IIP-IDP18-a-idp-01";
    public static final String ENCRYPTED_ID = "IIP-IDP19-a-idp-01";
    public static final String MULTI_KEY_ID = "IIP-IDP19-c-idp-01";
    private final String caseId;
    private static final String P = SamlLogoutRequestFactory.PROTOCOL;
    private static final String A = SamlLogoutRequestFactory.ASSERTION;
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String VERSION = "slo-basic-v5";
    public record Configuration(IdpErrorProbeConfiguration login, URI logoutEndpoint, URI suiteLogoutEndpoint,
            String targetIssuer, PlanCredentials suiteCredentials, List<X509Certificate> targetSigningCertificates, Binding logoutBinding, java.security.PublicKey targetEncryptionKey, List<java.security.PublicKey> targetEncryptionKeys, List<java.security.PublicKey> publishedEncryptionKeys) {
        public Configuration(IdpErrorProbeConfiguration login, URI logoutEndpoint, URI suiteLogoutEndpoint,
                String targetIssuer, PlanCredentials suiteCredentials, List<X509Certificate> targetSigningCertificates,
                Binding logoutBinding, java.security.PublicKey targetEncryptionKey, List<java.security.PublicKey> targetEncryptionKeys) {
            this(login,logoutEndpoint,suiteLogoutEndpoint,targetIssuer,suiteCredentials,targetSigningCertificates,
                    logoutBinding,targetEncryptionKey,targetEncryptionKeys,targetEncryptionKeys);
        }
        public Configuration(IdpErrorProbeConfiguration login, URI logoutEndpoint, URI suiteLogoutEndpoint,
                String targetIssuer, PlanCredentials suiteCredentials, List<X509Certificate> targetSigningCertificates,
                Binding logoutBinding, java.security.PublicKey targetEncryptionKey) {
            this(login,logoutEndpoint,suiteLogoutEndpoint,targetIssuer,suiteCredentials,targetSigningCertificates,
                    logoutBinding,targetEncryptionKey,targetEncryptionKey==null?List.of():List.of(targetEncryptionKey));
        }
        public Configuration(IdpErrorProbeConfiguration login, URI logoutEndpoint, URI suiteLogoutEndpoint,
                String targetIssuer, PlanCredentials suiteCredentials, List<X509Certificate> targetSigningCertificates, Binding logoutBinding) {
            this(login,logoutEndpoint,suiteLogoutEndpoint,targetIssuer,suiteCredentials,targetSigningCertificates,logoutBinding,null);
        }
        public Configuration(IdpErrorProbeConfiguration login, URI logoutEndpoint, URI suiteLogoutEndpoint,
                String targetIssuer, PlanCredentials suiteCredentials, List<X509Certificate> targetSigningCertificates) {
            this(login, logoutEndpoint, suiteLogoutEndpoint, targetIssuer, suiteCredentials, targetSigningCertificates, Binding.HTTP_POST);
        }
        public Configuration { Objects.requireNonNull(login); Objects.requireNonNull(logoutBinding); targetSigningCertificates = List.copyOf(targetSigningCertificates); targetEncryptionKeys = List.copyOf(targetEncryptionKeys); publishedEncryptionKeys = List.copyOf(publishedEncryptionKeys); }
    }
    private final Function<String, Configuration> configurations;
    private final SamlLogoutRequestFactory logout = new SamlLogoutRequestFactory();
    private final XmlSignatureVerifier signatures = new XmlSignatureVerifier();
    private final SamlXmlDecrypter decrypter = new SamlXmlDecrypter();
    public IdpBasicLogoutScenarioTestCase(Function<String, Configuration> configurations) {
        this(ID, configurations);
    }
    public IdpBasicLogoutScenarioTestCase(String caseId, Function<String, Configuration> configurations) {
        if (!List.of(ID, REDIRECT_ID, ENCRYPTED_ID, MULTI_KEY_ID).contains(caseId)) throw new IllegalArgumentException("Unsupported logout scenario");
        this.caseId = caseId;
        this.configurations = Objects.requireNonNull(configurations);
    }
    private boolean encryptedScenario() { return ENCRYPTED_ID.equals(caseId) || MULTI_KEY_ID.equals(caseId); }
    private String encryptionReason(String suffix) { return (MULTI_KEY_ID.equals(caseId) ? "slo.encrypted-id.multiple-keys." : "slo.encrypted-id.") + suffix; }
    @Override public String id() { return caseId; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public boolean plansFreshSessionBoundary() { return true; }
    @Override public boolean requiresFreshSession(CaseState state) { return String.valueOf(state.data().get("stage")).startsWith("login"); }
    @Override public Binding outboundBinding(CaseState state) {
        return Binding.valueOf((String) state.data().getOrDefault("outbound_binding", Binding.HTTP_POST.name()));
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }
    @Override public String browserInstructionsEn() {
        if (MULTI_KEY_ID.equals(caseId)) return "Log in using a fresh browser session. SAMLscope first tests rejection of an unregistered encryption key, "
                + "then starts a fresh login and encrypts the identifier with the second distinct registered encryption key. "
                + "Both correlated signed responses are required; do not enter a verdict.";
        if (encryptedScenario()) return "Log in using a fresh browser session. SAMLscope first sends an encrypted identifier "
                + "using an unregistered key. After a verified rejection, log in with a fresh session again to test the registered key. "
                + "The Suite checks signed protocol responses; do not enter a verdict.";
        return "Start with a fresh browser session and log in. SAMLscope sends a signed synchronous LogoutRequest "
                + "using the issued identifier and SessionIndex, then checks the correlated LogoutResponse. Do not enter a verdict.";
    }
    @Override public CaseStep start(CaseContext context) {
        if (!context.transcriptComplete()) return finish(Outcome.NOT_VERIFIED,"slo.basic.history-incomplete",List.of());
        var c = configurations.apply(context.runId());
        if (REDIRECT_ID.equals(caseId) && c.logoutBinding() != Binding.SIGNED_REDIRECT)
            return finish(Outcome.NOT_VERIFIED, "slo.redirect.configuration-unavailable", List.of());
        if (!c.login().preconditionsSatisfied() || c.logoutEndpoint() == null || c.suiteLogoutEndpoint() == null
                || c.suiteCredentials() == null || c.targetSigningCertificates().isEmpty() || c.targetIssuer() == null)
            return finish(Outcome.NOT_VERIFIED, "slo.basic.preconditions-unmet", List.of());
        if (encryptedScenario()) {
            var usable = usableKeys(c);
            if (MULTI_KEY_ID.equals(caseId)) {
                if (usable.size() < 2
                        || usable.stream().map(k -> Base64.getEncoder().encodeToString(k.getEncoded())).distinct().count() != usable.size())
                    return finish(Outcome.NOT_VERIFIED,encryptionReason("configuration-unavailable"),List.of());
            } else if (usable.isEmpty()) {
                return finish(Outcome.NOT_VERIFIED,encryptionReason("key-unavailable"),List.of());
            }
        }
        return beginLogin(context,c,encryptedScenario()?"login-control":"login",List.of());
    }
    /** Registered target keys only: the Suite key is the unregistered control and never a positive recipient. */
    private static List<java.security.PublicKey> usableKeys(Configuration c) {
        var suite = c.suiteCredentials().certificate().getPublicKey();
        return c.targetEncryptionKeys().stream()
                .filter(key -> "RSA".equals(key.getAlgorithm()))
                .filter(key -> !Arrays.equals(key.getEncoded(), suite.getEncoded())).toList();
    }
    private CaseStep beginLogin(CaseContext context, Configuration c, String stage, List<EvidenceRef> evidence) {
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-"+stage, 0);
        var xml = new SamlErrorProbeRequestFactory().build(SamlErrorProbeRequestFactory.Probe.BASELINE_SUCCESS,
                "_"+action, c.login().ssoEndpoint(), c.login().suiteIssuer(), c.login().registeredAcs(), context.clock().instant());
        var document = SecureXml.parse(xml); var root = document.getDocumentElement();
        new XmlSigner().sign(root, c.suiteCredentials(), children(root,A,"Issuer").getFirst().getNextSibling() instanceof Element e ? e : null);
        return await(context, c, stage, action, OutboundKind.AUTHN_REQUEST, SecureXml.serialize(document), c.login().ssoEndpoint(), evidence);
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!caseId.equals(state.data().get("case_id")) || !VERSION.equals(state.data().get("definition")) || !List.of("login","logout","login-control","logout-control").contains(state.data().get("stage")))
            return finish(Outcome.NOT_VERIFIED,"slo.basic.scenario-changed",List.of());
        var evidence = new ArrayList<EvidenceRef>();
        if (state.data().get("evidence") instanceof List<?> refs)
            for (var ref : refs) if (ref instanceof String s) evidence.add(new EvidenceRef("transcript",s));
        boolean login = String.valueOf(state.data().get("stage")).startsWith("login");
        if (event instanceof CaseEvent.Aborted || event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.InboundUnavailable)
            return finish(Outcome.NOT_VERIFIED,login ? "slo.basic.control-unavailable" : "slo.basic.response-unavailable",evidence);
        if (!(event instanceof CaseEvent.InboundMessage inbound) || !"transcript".equals(inbound.evidence().kind()))
            throw new IllegalArgumentException("SLO scenario requires recorded inbound XML");
        evidence.add(inbound.evidence());
        if (!context.transcriptComplete()) return finish(Outcome.NOT_VERIFIED,"slo.basic.history-incomplete",evidence);
        var c = configurations.apply(context.runId());
        try {
            var root = SecureXml.parse(inbound.decodedSaml()).getDocumentElement();
            if (login) return afterLogin(context, c, state, root, evidence);
            if (!is(root,P,"LogoutResponse") || !(trusted(root,c) || trustedRedirect(context,c,inbound)) || children(root,A,"Issuer").size()!=1
                    || !c.targetIssuer().equals(children(root,A,"Issuer").getFirst().getTextContent()))
                return finish(Outcome.NOT_VERIFIED,"slo.basic.response-unverifiable",evidence);
            if (!Objects.equals(state.data().get("request_id"),root.getAttribute("InResponseTo"))
                    || !c.suiteLogoutEndpoint().toString().equals(root.getAttribute("Destination")))
                return finish(encryptedScenario()?Outcome.NOT_VERIFIED:Outcome.VIOLATED,"slo.basic.original-requester-mismatch",evidence);
            if (!SamlSchemaValidation.isValid(root,SamlSchemaValidation.SchemaKind.PROTOCOL))
                return finish(Outcome.NOT_VERIFIED,"slo.basic.response-structure-unverified",evidence);
            if (encryptedScenario()) {
                if ("logout-control".equals(state.data().get("stage"))) {
                    if (SUCCESS.equals(status(root))) return finish(Outcome.NOT_VERIFIED,encryptionReason("negative-control-failed"),evidence);
                    return beginLogin(context,c,"login",evidence);
                }
                var source=state.data().get("decryption_key_source");
                var details=(source instanceof String value && List.of("published-metadata","supplemental-input").contains(value))
                        ? Map.<String,Object>of("decryption_key_source",List.of(value)) : Map.<String,Object>of();
                return SUCCESS.equals(status(root))
                        ? finish(Outcome.SATISFIED,encryptionReason("decryption-observed"),evidence,details)
                        : finish(Outcome.VIOLATED,encryptionReason("rejected"),evidence,details);
            }
            if (REDIRECT_ID.equals(caseId)) {
                return SUCCESS.equals(status(root))
                        ? finish(Outcome.SATISFIED,"slo.redirect.logout-request-accepted.satisfied",evidence)
                        : finish(Outcome.VIOLATED,"slo.redirect.logout-request-rejected",evidence);
            }
            // G1 explicitly assigns session termination and status branching to IDP17.e/o/q.
            return finish(Outcome.SATISFIED,"slo.basic.synchronous-response-observed",evidence);
        } catch (RuntimeException invalid) {
            return finish(Outcome.NOT_VERIFIED,login ? "slo.basic.control-unverifiable" : "slo.basic.response-unverifiable",evidence);
        }
    }
    private CaseStep afterLogin(CaseContext context, Configuration c, CaseState state, Element root, List<EvidenceRef> evidence) {
        if (!is(root,P,"Response") || !"2.0".equals(root.getAttribute("Version"))
                || !Objects.equals(state.data().get("request_id"),root.getAttribute("InResponseTo"))
                || !c.login().registeredAcs().toString().equals(root.getAttribute("Destination"))
                || !SUCCESS.equals(status(root)) || !SamlSchemaValidation.isValid(root,SamlSchemaValidation.SchemaKind.PROTOCOL))
            return finish(Outcome.NOT_VERIFIED,"slo.basic.control-unverifiable",evidence);
        var assertions = new ArrayList<>(children(root,A,"Assertion"));
        for (var encrypted : children(root,A,"EncryptedAssertion"))
            assertions.add(decrypter.decrypt(encrypted,c.suiteCredentials().privateKey()));
        if (assertions.size()!=1 || !is(assertions.getFirst(),A,"Assertion"))
            return finish(Outcome.NOT_VERIFIED,"slo.basic.session-unverifiable",evidence);
        var assertion = assertions.getFirst();
        if (!SamlSchemaValidation.isValid(assertion,SamlSchemaValidation.SchemaKind.ASSERTION)
                || (!trusted(root,c) && !trusted(assertion,c)) || children(assertion,A,"Issuer").size()!=1
                || !c.targetIssuer().equals(children(assertion,A,"Issuer").getFirst().getTextContent()))
            return finish(Outcome.NOT_VERIFIED,"slo.basic.control-unverifiable",evidence);
        var subjects=children(assertion,A,"Subject");
        if (subjects.size()!=1) return finish(Outcome.NOT_VERIFIED,"slo.basic.session-unverifiable",evidence);
        var names=new ArrayList<>(children(subjects.getFirst(),A,"NameID"));
        for (var encrypted : children(subjects.getFirst(),A,"EncryptedID"))
            names.add(decrypter.decrypt(encrypted,c.suiteCredentials().privateKey()));
        var indexes=children(assertion,A,"AuthnStatement").stream().map(e->e.getAttribute("SessionIndex")).toList();
        if (names.size()!=1 || !is(names.getFirst(),A,"NameID") || !children(subjects.getFirst(),A,"BaseID").isEmpty()
                || indexes.isEmpty() || indexes.stream().anyMatch(String::isBlank))
            return finish(Outcome.NOT_VERIFIED,"slo.basic.session-unverifiable",evidence);
        var control="login-control".equals(state.data().get("stage"));
        var stage=control?"logout-control":"logout";
        var identifier=names.getFirst();
        String keySource=null;
        if (encryptedScenario()) {
            var required=MULTI_KEY_ID.equals(caseId)?2:1;
            var usable=usableKeys(c);
            if (usable.size()<required)
                return finish(Outcome.NOT_VERIFIED,encryptionReason(MULTI_KEY_ID.equals(caseId)?"configuration-unavailable":"key-unavailable"),evidence);
            var key=control?c.suiteCredentials().certificate().getPublicKey():usable.get(MULTI_KEY_ID.equals(caseId)?1:0);
            if(!control) keySource=c.publishedEncryptionKeys().stream()
                    .anyMatch(published->Arrays.equals(published.getEncoded(),key.getEncoded()))
                    ?"published-metadata":"supplemental-input";
            identifier=logout.encryptedIdentifier(identifier,key,new SamlEncryptionFixtureFactory.Algorithms(
                    SamlEncryptionFixtureFactory.Content.AES128_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                    SamlEncryptionFixtureFactory.Digest.DEFAULT,SamlEncryptionFixtureFactory.Mgf.DEFAULT));
        }
        var action=ActionIds.derive(context.runId(),caseId,VERSION+"-"+stage,0);
        var payload=logout.sign(logout.build("_"+action,c.logoutEndpoint(),c.login().suiteIssuer(),identifier,indexes,
                context.clock().instant(),null,false),c.suiteCredentials());
        return await(context,c,stage,action,OutboundKind.LOGOUT_REQUEST,payload,c.logoutEndpoint(),evidence,keySource);
    }
    private CaseStep await(CaseContext context, Configuration c, String stage, String action, OutboundKind kind,
            byte[] payload, URI target, List<EvidenceRef> evidence) {
        return await(context,c,stage,action,kind,payload,target,evidence,null);
    }
    private CaseStep await(CaseContext context, Configuration c, String stage, String action, OutboundKind kind,
            byte[] payload, URI target, List<EvidenceRef> evidence, String keySource) {
        var data=new java.util.LinkedHashMap<String,Object>();
        data.put("definition",VERSION);data.put("stage",stage);data.put("case_id",caseId);
        data.put("request_id","_"+action);data.put("fixture_id","slo-basic-"+stage);
        data.put("outbound_binding",(stage.startsWith("logout") ? c.logoutBinding() : Binding.HTTP_POST).name());
        data.put("evidence",evidence.stream().map(EvidenceRef::reference).toList());
        if(keySource!=null)data.put("decryption_key_source",keySource);
        return new CaseStep.AwaitInbound(new CaseState(VERSION+"-"+stage,Map.copyOf(data)),
                List.of(new OutboundAction(action,kind,payload,target,false)),
                new InboundMatcher("saml-response",Map.of("ScenarioActionId",action)),c.login().responseTimeout());
    }
    private boolean trustedRedirect(CaseContext context, Configuration c, CaseEvent.InboundMessage inbound) {
        var entries = context.transcript().list(context.runId()).stream()
                .filter(entry -> inbound.evidence().reference().equals(entry.id())).toList();
        if (entries.size() != 1) return false;
        var entry = entries.getFirst();
        if (!context.runId().equals(entry.runId())
                || entry.direction() != com.samlscope.core.transcript.Direction.INBOUND
                || !"GET".equalsIgnoreCase(entry.method())) return false;
        var verifier = new com.samlscope.saml.binding.RedirectSignatureVerifier();
        return c.targetSigningCertificates().stream().anyMatch(cert ->
                verifier.isValidForMessage(entry.rawQuery(), cert, inbound.decodedSaml()));
    }
    private boolean trusted(Element root, Configuration c) {
        return c.targetSigningCertificates().stream().anyMatch(cert->signatures.hasValidEnvelopedSignature(root,cert));
    }
    private String status(Element root) {
        var statuses=children(root,P,"Status"); if(statuses.size()!=1)return "";
        var codes=children(statuses.getFirst(),P,"StatusCode");return codes.size()==1 ? codes.getFirst().getAttribute("Value") : "";
    }
    private static boolean is(Element e,String ns,String name) { return ns.equals(e.getNamespaceURI()) && name.equals(e.getLocalName()); }
    private static List<Element> children(Element root,String ns,String name) {
        var result=new ArrayList<Element>();
        for(var n=root.getFirstChild();n!=null;n=n.getNextSibling()) if(n instanceof Element e && is(e,ns,name))result.add(e);
        return result;
    }
    private CaseStep finish(Outcome outcome,String reason,List<EvidenceRef> evidence) {
        return finish(outcome,reason,evidence,Map.of());
    }
    private CaseStep finish(Outcome outcome,String reason,List<EvidenceRef> evidence,Map<String,Object> details) {
        return new CaseStep.Finish(new CaseOutcome(outcome,outcome==Outcome.NOT_VERIFIED ? reason : null,reason,reason,List.copyOf(evidence),details));
    }
}
