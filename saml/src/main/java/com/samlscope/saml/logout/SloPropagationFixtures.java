package com.samlscope.saml.logout;

import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import org.w3c.dom.Element;

/** A Run-scoped, signed three-participant SOAP propagation preparation. */
public final class SloPropagationFixtures {
    public static final String CASE = "IIP-IDP17-r-idp-01";
    public static final String MARKER = "error-v2";
    public static final List<String> PARTICIPANTS = List.of("fail", "remain", "remain2");
    private static final String RUN = "run_[0-9A-HJKMNP-TV-Z]{26}";

    private SloPropagationFixtures() {}

    /** Explicit deployment input shared by the case and peer; never taken from an incoming marker. */
    public static URI configuredBackchannelBase(URI defaultBase) {
        var configured = System.getenv("SAMLSCOPE_SLO_BACKCHANNEL_BASE");
        var result = configured == null || configured.isBlank() ? defaultBase : URI.create(configured);
        checkBase(result); return result;
    }

    public static String variant(String trial) { checkTrial(trial); return "slo-propagation-soap-" + trial; }

    /** The error belongs to the first verified arrival, never to a participant label. */
    public static String mode(String trial) { checkTrial(trial); return "failure".equals(trial) ? "first-arrival" : "all-success"; }

    public static URI participantEntity(URI base, TestPlan plan, String participant) {
        checkParticipant(participant);
        return URI.create(base + "/p/" + plan.id() + "/sp-" + participant);
    }

    public static URI participantEndpoint(URI base, TestPlan plan, String run, String trial, String participant) {
        check(plan, run, trial); checkParticipant(participant);
        checkBase(base);
        return URI.create(base + "/p/" + plan.id() + "/sp/slo/soap?run=" + run
                + "&propagation=" + MARKER + "&participant=" + participant + "&trial=" + trial + "&mode=" + mode(trial));
    }

    public static byte[] prepare(URI base, FilePlanKeyStore keys, XmlSigner signer,
            TestPlan plan, String run, String trial, Instant at) {
        check(plan, run, trial);
        if (at == null) throw new SamlException("Propagation preparation needs an original timestamp");
        return prepare(URI.create(base + "/p/" + plan.id()), URI.create(base + "/p/" + plan.id() + "/sp/acs/0"),
                keys.getOrCreate(plan.id()), run, trial, at, configuredBackchannelBase(base));
    }

    /** The case and peer share this factory; it needs no repository or administrative service. */
    public static byte[] prepare(URI suiteEntity, URI registeredAcs, PlanCredentials credentials,
            String run, String trial, Instant at) {
        var suffix = "/p/";
        if (suiteEntity == null || suiteEntity.toString().lastIndexOf(suffix) < 0)
            throw new SamlException("Foreign propagation Suite entity");
        var base = URI.create(suiteEntity.toString().substring(0, suiteEntity.toString().lastIndexOf(suffix)));
        return prepare(suiteEntity, registeredAcs, credentials, run, trial, at, configuredBackchannelBase(base));
    }

    public static byte[] prepare(URI suiteEntity, URI registeredAcs, PlanCredentials credentials,
            String run, String trial, Instant at, URI backchannelBase) {
        checkTrial(trial);
        checkBase(backchannelBase);
        if (suiteEntity == null || !suiteEntity.isAbsolute() || !List.of("http", "https").contains(suiteEntity.getScheme())
                || suiteEntity.getHost() == null || suiteEntity.getRawUserInfo() != null || suiteEntity.getRawQuery() != null
                || suiteEntity.getRawFragment() != null || !suiteEntity.getPath().matches(".*/p/plan_[0-9A-HJKMNP-TV-Z]{26}")
                || registeredAcs == null || !registeredAcs.equals(URI.create(suiteEntity + "/sp/acs/0"))
                || run == null || !run.matches(RUN) || at == null || credentials == null)
            throw new SamlException("Foreign propagation preparation inputs");
        var planSuffix = suiteEntity.getPath().substring(suiteEntity.getPath().lastIndexOf("/p/"));
        var callbackEntity = backchannelBase + planSuffix;
        var document = SecureXml.newDocument();
        var aggregate = document.createElementNS(MetadataService.MD, "md:EntitiesDescriptor");
        aggregate.setAttributeNS(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MetadataService.MD);
        aggregate.setAttributeNS(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", MetadataService.DS);
        aggregate.setAttribute("ID", "_" + run + "_slo_propagation_" + trial.replace('-', '_'));
        document.appendChild(aggregate);
        for (var participant : List.of("primary", "fail", "remain", "remain2")) {
            var entity = document.createElementNS(MetadataService.MD, "md:EntityDescriptor");
            entity.setAttribute("ID", "_" + run + "_" + participant);
            entity.setAttribute("entityID", suiteEntity + ("primary".equals(participant) ? "" : "/sp-" + participant));
            entity.setAttribute("validUntil", at.plus(java.time.Duration.ofDays(14)).toString());
            var role = document.createElementNS(MetadataService.MD, "md:SPSSODescriptor");
            role.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
            role.setAttribute("AuthnRequestsSigned", "false"); role.setAttribute("WantAssertionsSigned", "true");
            entity.appendChild(role);
            for (var use : List.of("signing", "encryption")) {
                var key = document.createElementNS(MetadataService.MD, "md:KeyDescriptor"); key.setAttribute("use", use);
                var info = document.createElementNS(MetadataService.DS, "ds:KeyInfo");
                var data = document.createElementNS(MetadataService.DS, "ds:X509Data");
                var certificate = document.createElementNS(MetadataService.DS, "ds:X509Certificate");
                try { certificate.setTextContent(java.util.Base64.getEncoder().encodeToString(credentials.certificate().getEncoded())); }
                catch (java.security.cert.CertificateEncodingException invalid) { throw new SamlException("Unusable propagation certificate", invalid); }
                data.appendChild(certificate); info.appendChild(data); key.appendChild(info); role.appendChild(key);
            }
            for (var binding : "primary".equals(participant)
                    ? List.of(MetadataService.REDIRECT, MetadataService.POST, MetadataService.SOAP) : List.of(MetadataService.SOAP)) {
                var endpoint = document.createElementNS(MetadataService.MD, "md:SingleLogoutService");
                endpoint.setAttribute("Binding", binding);
                endpoint.setAttribute("Location", "primary".equals(participant)
                        ? (MetadataService.SOAP.equals(binding) ? callbackEntity : suiteEntity) + "/sp/slo" + (MetadataService.SOAP.equals(binding) ? "/soap" : "")
                        : callbackEntity + "/sp/slo/soap?run=" + run + "&propagation=" + MARKER + "&participant=" + participant + "&trial=" + trial + "&mode=" + mode(trial));
                role.appendChild(endpoint);
            }
            var acs = document.createElementNS(MetadataService.MD, "md:AssertionConsumerService");
            acs.setAttribute("Binding", MetadataService.POST); acs.setAttribute("Location", registeredAcs.toString());
            acs.setAttribute("index", "0"); acs.setAttribute("isDefault", "true"); role.appendChild(acs);
            aggregate.appendChild(entity);
        }
        new XmlSigner().sign(aggregate, credentials, (Element) aggregate.getFirstChild());
        return SecureXml.serialize(document);
    }

    /** Check genuine prepared bytes, including signature, without assuming randomized signatures repeat. */
    public static boolean matches(byte[] original, URI base, FilePlanKeyStore keys, XmlSigner signer,
            TestPlan plan, String run, String trial, Instant at) {
        try {
            var document = SecureXml.parse(original);
            var root = document.getDocumentElement();
            if (!MetadataService.MD.equals(root.getNamespaceURI()) || !"EntitiesDescriptor".equals(root.getLocalName())) return false;
            var verifier = new XmlSignatureVerifier();
            if (!verifier.hasValidEnvelopedReferenceDigests(root)
                    || !verifier.hasValidEnvelopedSignature(root, keys.getOrCreate(plan.id()).certificate())) return false;
            var expected = SecureXml.parse(prepare(base, keys, signer, plan, run, trial, at));
            removeSignatures(root); removeSignatures(expected.getDocumentElement());
            return Arrays.equals(SecureXml.serialize(document), SecureXml.serialize(expected));
        } catch (RuntimeException invalid) { return false; }
    }

    private static void removeSignatures(Element root) {
        var signatures = root.getElementsByTagNameNS(MetadataService.DS, "Signature");
        for (int i = signatures.getLength() - 1; i >= 0; i--) {
            var signature = signatures.item(i); signature.getParentNode().removeChild(signature);
        }
    }
    private static void check(TestPlan plan, String run, String trial) {
        if (plan == null || plan.profile() != FunctionalProfile.SINGLE_LOGOUT_IDP
                || run == null || !run.matches(RUN)) throw new SamlException("Foreign propagation Run or profile");
        checkTrial(trial);
    }
    private static void checkTrial(String trial) {
        if (!List.of("failure", "all-success").contains(trial)) throw new SamlException("Unknown propagation trial");
    }
    private static void checkParticipant(String participant) {
        if (!PARTICIPANTS.contains(participant)) throw new SamlException("Unknown propagation participant");
    }
    private static void checkBase(URI base) {
        if (base == null || !base.isAbsolute() || !List.of("http", "https").contains(base.getScheme())
                || base.getHost() == null || base.getRawUserInfo() != null || base.getRawQuery() != null
                || base.getRawFragment() != null || !(base.getRawPath().isEmpty() || "/".equals(base.getRawPath())))
            throw new SamlException("Propagation backchannel base must be a configured HTTP origin");
        if ("/".equals(base.getRawPath())) throw new SamlException("Propagation backchannel base must omit its trailing slash");
    }
}
