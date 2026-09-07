package com.samlscope.runner;

import java.util.function.BiFunction;
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
        if (plan.parameters().requestSigningMode() != TestPlan.RequestSigningMode.REQUIRED
                || action.kind() != OutboundKind.AUTHN_REQUEST) return action;
        var document = SecureXml.parse(action.payload());
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
        return new OutboundAction(action.actionId(), action.kind(), SecureXml.serialize(document),
                action.target(), action.requiresEphemeralCredential());
    }
}
