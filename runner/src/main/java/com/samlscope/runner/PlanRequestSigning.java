package com.samlscope.runner;

import java.util.function.BiFunction;
import java.nio.charset.StandardCharsets;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.RunRepository;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Applies the Plan's transport precondition before the outbox intent is persisted. */
public final class PlanRequestSigning implements BiFunction<String, OutboundAction, OutboundAction> {
    private static final String SIMPLE_DTD = "<!DOCTYPE samlp:AuthnRequest>";
    private static final String EXTERNAL_DTD = "<!DOCTYPE samlp:AuthnRequest [<!ENTITY % samlscope SYSTEM \"https://invalid.example/samlscope.dtd\"> %samlscope;]>";
    private final PlanRepository plans;
    private final RunRepository runs;
    private final FilePlanKeyStore keys;

    public PlanRequestSigning(PlanRepository plans, RunRepository runs, FilePlanKeyStore keys) {
        this.plans = plans;
        this.runs = runs;
        this.keys = keys;
    }

    @Override public OutboundAction apply(String runId, OutboundAction action) {
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Missing Plan"));
        if (action.kind() != OutboundKind.AUTHN_REQUEST) return action;
        if (action.requestSigning() == OutboundAction.RequestSigning.OMIT_FOR_IDP12_B) return action;
        var signingRequired = action.requestSigning() == OutboundAction.RequestSigning.REQUIRE
                || plan.parameters().requestSigningMode() == TestPlan.RequestSigningMode.REQUIRED;
        if (!signingRequired) return action;
        // G03's two approved DTD fixtures are the only exceptional inputs. Remove the
        // literal declaration before secure parsing/signing, then restore it outside the
        // signed AuthnRequest. Never parse or resolve the DTD (including its entity URL).
        var raw = new String(action.payload(), StandardCharsets.UTF_8);
        var dtd = raw.contains(EXTERNAL_DTD) ? EXTERNAL_DTD
                : raw.contains(SIMPLE_DTD) ? SIMPLE_DTD : null;
        if (dtd != null) {
            var declarationEnd = raw.indexOf("?>");
            var position = declarationEnd >= 0 ? declarationEnd + 2 : 0;
            if (!raw.startsWith(dtd, position) || raw.indexOf("<!DOCTYPE", position + dtd.length()) >= 0) {
                throw new SamlException("Unexpected DTD fixture layout");
            }
            raw = raw.substring(0, position) + raw.substring(position + dtd.length());
        }
        var document = SecureXml.parse(raw.getBytes(StandardCharsets.UTF_8));
        var root = document.getDocumentElement();
        if (!"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())
                || !"AuthnRequest".equals(root.getLocalName())) {
            throw new SamlException("Fixture cannot be signed as an AuthnRequest");
        }
        // Existing signatures include deliberately broken references, values and transforms.
        // Never repair or reserialize them, including signatures in unusual locations.
        if (root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength() > 0) {
            return action;
        }
        // An AuthnRequest without @ID cannot carry a same-document reference signature. The
        // approved invalid-request scenario deliberately sends such a malformed request; the
        // case oracle, not the Plan transport precondition, decides whether a response is
        // conformant, so the request is persisted unchanged.
        if (root.getAttribute("ID").isBlank()) return action;
        Element before = null;
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element
                    && !("urn:oasis:names:tc:SAML:2.0:assertion".equals(element.getNamespaceURI())
                    && "Issuer".equals(element.getLocalName()))) {
                before = element;
                break;
            }
        }
        new XmlSigner().sign(root, keys.getOrCreate(plan.id()), before);
        var signed = com.samlscope.saml.normal.ProviderNameWireFormat.preserve(
                raw.getBytes(StandardCharsets.UTF_8), SecureXml.serialize(document));
        if (dtd != null) {
            var xml = new String(signed, StandardCharsets.UTF_8);
            var declarationEnd = xml.indexOf("?>");
            var position = declarationEnd >= 0 ? declarationEnd + 2 : 0;
            signed = (xml.substring(0, position) + dtd + xml.substring(position)).getBytes(StandardCharsets.UTF_8);
        }
        return new OutboundAction(action.actionId(), action.kind(), signed,
                action.target(), action.requiresEphemeralCredential(), action.requestSigning());
    }
}
