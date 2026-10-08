package com.samlscope.runner.cases;

import com.samlscope.core.casedef.CaseDefinitionCatalog.ControlKind;
import com.samlscope.core.plan.TargetRole;
import java.nio.charset.StandardCharsets;

/** Deterministic projections of the approved a8 controls, explicitly Suite calibration only.
 * The retrieved reference body stays fixed; the negative projection changes only @namespace. */
final class AdditionalMetadataLocationControlProducer {
    static final String TYPE = "SuiteMetadataNamespaceControl";
    private AdditionalMetadataLocationControlProducer() {}
    static byte[] bytes(TargetRole role, AdditionalMetadataLocationEvidence.Original original, ControlKind kind) {
        String namespace = original.rootNamespace();
        if (kind == ControlKind.NEGATIVE) {
            namespace = "urn:samlscope:calibration:namespace-mismatch:" + AdditionalMetadataLocationEvidence.hash(original.body());
            if (namespace.equals(original.rootNamespace())) namespace += ":different";
        }
        String descriptor = role == TargetRole.IDP ? "IDPSSODescriptor" : "SPSSODescriptor";
        return ("<md:EntityDescriptor xmlns:md='" + AdditionalMetadataLocationEvidence.MD
                + "' entityID='urn:samlscope:calibration:additional-metadata-location'>"
                + "<md:" + descriptor + " protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
                + (role == TargetRole.IDP
                    ? "<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://suite.invalid/calibration/sso'/>"
                    : "<md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://suite.invalid/calibration/acs' index='0'/>")
                + "</md:" + descriptor + ">"
                + "<md:AdditionalMetadataLocation namespace='" + escape(namespace) + "'>"
                + escape(original.request().url().toString()) + "</md:AdditionalMetadataLocation></md:EntityDescriptor>")
                .getBytes(StandardCharsets.UTF_8);
    }
    private static String escape(String value) { return value.replace("&", "&amp;").replace("'", "&apos;")
            .replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"); }
}
