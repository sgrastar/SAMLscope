package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Prevents role keys and independently signed child metadata from substituting for document KeyInfo. */
class MetadataSignatureKeyInfoScopeTest {
    private static final String DOCUMENT_CERTIFICATE = certificate("document-signature-certificate");
    private static final String OTHER_CERTIFICATE = certificate("other-role-or-child-certificate");
    private static final String NAMESPACES = " xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\""
            + " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";

    @Test
    void roleKeyBeforeDocumentSignatureDoesNotBecomeTheEmbeddedTrustKey() throws Exception {
        var role = "<md:SPSSODescriptor><md:KeyDescriptor>" + keyInfo(OTHER_CERTIFICATE)
                + "</md:KeyDescriptor></md:SPSSODescriptor>";
        assertDocumentCertificate(entity(role + signature(DOCUMENT_CERTIFICATE)));
    }

    @Test
    void omittedSignatureKeyInfoCannotBorrowAPublishedRoleCertificate() {
        var role = "<md:SPSSODescriptor><md:KeyDescriptor>" + keyInfo(OTHER_CERTIFICATE)
                + "</md:KeyDescriptor></md:SPSSODescriptor>";
        assertUnproven(entity("<ds:Signature/>" + role));
    }

    @Test
    void separatelySignedChildEntityCannotSubstituteForAnUnsignedDocument() {
        var child = "<md:EntityDescriptor entityID=\"https://child.example/sp\">"
                + signature(OTHER_CERTIFICATE) + "</md:EntityDescriptor>";
        assertUnproven(entities(child));
    }

    @Test
    void parentDocumentSignatureIsIndependentOfItsSignedChild() throws Exception {
        var child = "<md:EntityDescriptor entityID=\"https://child.example/sp\">"
                + signature(OTHER_CERTIFICATE) + "</md:EntityDescriptor>";
        assertDocumentCertificate(entities(child + signature(DOCUMENT_CERTIFICATE)));
    }

    @Test
    void documentSignatureCannotBorrowKeyInfoFromANestedSignature() {
        assertUnproven(entity("<ds:Signature>" + signature(OTHER_CERTIFICATE) + "</ds:Signature>"));
    }

    @Test
    void multipleDocumentSignaturesOrCertificateChoicesAreUnproven() {
        assertUnproven(entity(signature(DOCUMENT_CERTIFICATE) + signature(OTHER_CERTIFICATE)));
        assertUnproven(entity("<ds:Signature>" + keyInfo(DOCUMENT_CERTIFICATE)
                + keyInfo(OTHER_CERTIFICATE) + "</ds:Signature>"));
        assertUnproven(entity("<ds:Signature><ds:KeyInfo><ds:X509Data>"
                + DOCUMENT_CERTIFICATE + OTHER_CERTIFICATE + "</ds:X509Data></ds:KeyInfo></ds:Signature>"));
        assertUnproven(entity("<ds:Signature><ds:KeyInfo><ds:X509Data>"
                + DOCUMENT_CERTIFICATE + "</ds:X509Data><ds:X509Data>" + OTHER_CERTIFICATE
                + "</ds:X509Data></ds:KeyInfo></ds:Signature>"));
    }

    @Test
    void foreignNamespaceAndIndirectCertificateScopesAreUnproven() {
        assertUnproven(entity("<Signature xmlns=\"https://foreign.example/signature\">"
                + keyInfo(DOCUMENT_CERTIFICATE) + "</Signature>"));
        assertUnproven(entity("<ds:Signature><ds:KeyInfo><ds:X509Data><md:Extensions>"
                + DOCUMENT_CERTIFICATE + "</md:Extensions></ds:X509Data></ds:KeyInfo></ds:Signature>"));
    }

    @Test
    void blankOrMalformedCertificateIsUnproven() {
        assertUnproven(entity(signature("<ds:X509Certificate> </ds:X509Certificate>")));
        assertUnproven(entity(signature("<ds:X509Certificate>not-base64!</ds:X509Certificate>")));
    }

    private static void assertDocumentCertificate(String xml) throws Exception {
        var expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest("document-signature-certificate".getBytes(StandardCharsets.UTF_8)));
        assertEquals(expected, MetadataSignatureVerificationEvidenceFile.embeddedKeyInfoCertificateSha256(
                xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static void assertUnproven(String xml) {
        assertThrows(IllegalArgumentException.class,
                () -> MetadataSignatureVerificationEvidenceFile.embeddedKeyInfoCertificateSha256(
                        xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static String entity(String children) {
        return "<md:EntityDescriptor" + NAMESPACES + " entityID=\"https://document.example/sp\">"
                + children + "</md:EntityDescriptor>";
    }

    private static String entities(String children) {
        return "<md:EntitiesDescriptor" + NAMESPACES + ">" + children + "</md:EntitiesDescriptor>";
    }

    private static String signature(String certificate) {
        return "<ds:Signature>" + keyInfo(certificate) + "</ds:Signature>";
    }

    private static String keyInfo(String certificate) {
        return "<ds:KeyInfo><ds:X509Data>" + certificate + "</ds:X509Data></ds:KeyInfo>";
    }

    private static String certificate(String bytes) {
        return "<ds:X509Certificate>" + Base64.getEncoder().encodeToString(bytes.getBytes(StandardCharsets.UTF_8))
                + "</ds:X509Certificate>";
    }
}
