package com.samlscope.runner.cases;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.xml.XMLConstants;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Static publisher-side checks proven by the target's own metadata document. */
final class TargetMetadataObservation {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String ALG = "urn:oasis:names:tc:SAML:metadata:algsupport";
    private static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    private static final String MDATTR = "urn:oasis:names:tc:SAML:metadata:attribute";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SAML2 = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final Set<String> LOCALIZED_UI_ELEMENTS = Set.of(
            "DisplayName", "Description", "InformationURL", "PrivacyStatementURL", "Keywords");
    private static final Set<String> ROLE_ELEMENTS = Set.of(
            "RoleDescriptor", "IDPSSODescriptor", "SPSSODescriptor", "AuthnAuthorityDescriptor",
            "AttributeAuthorityDescriptor", "PDPDescriptor");
    private static final Set<String> CONCRETE_SAML_ROLE_ELEMENTS = Set.of(
            "IDPSSODescriptor", "SPSSODescriptor", "AuthnAuthorityDescriptor",
            "AttributeAuthorityDescriptor", "PDPDescriptor");
    private static final Set<String> ONE_DIRECTION_ENDPOINTS = Set.of(
            "ArtifactResolutionService", "NameIDMappingService", "SingleSignOnService");
    private static final Set<String> DATA_ENCRYPTION = Set.of(
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            "http://www.w3.org/2009/xmlenc11#aes192-gcm",
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
    private static final Set<String> KEY_TRANSPORT_OR_AGREEMENT = Set.of(
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            "http://www.w3.org/2009/xmlenc11#ECDH-ES");

    private TargetMetadataObservation() {}

    static boolean supports(String caseId) {
        return isAlgorithmPublicationCapability(caseId)
                || suffix(caseId, "a3") || suffix(caseId, "a6") || suffix(caseId, "a7")
                || suffix(caseId, "a9") || suffix(caseId, "ab") || idpSuffix(caseId, "ae")
                || suffix(caseId, "c8") || suffix(caseId, "c9") || suffix(caseId, "ca")
                || suffix(caseId, "cb") || suffix(caseId, "cc") || suffix(caseId, "ce")
                || suffix(caseId, "d2") || suffix(caseId, "d3") || suffix(caseId, "d4")
                || suffix(caseId, "d5") || suffix(caseId, "d6") || suffix(caseId, "d7")
                || suffix(caseId, "d8") || suffix(caseId, "d9")
                || suffix(caseId, "e1") || suffix(caseId, "e2") || suffix(caseId, "e3")
                || suffix(caseId, "e4") || idpSuffix(caseId, "e5") || suffix(caseId, "e6") || suffix(caseId, "ed")
                || suffix(caseId, "ec") || suffix(caseId, "f1") || suffix(caseId, "f2")
                || suffix(caseId, "f3") || suffix(caseId, "f4") || suffix(caseId, "fk")
                || idpSuffix(caseId, "f7") || suffix(caseId, "f8") || suffix(caseId, "fa")
                || idpSuffix(caseId, "fc") || idpSuffix(caseId, "fd") || idpSuffix(caseId, "fe");
    }

    static Optional<CaseOutcome> evaluate(String caseId, byte[] metadata, Instant now) {
        if (!supports(caseId) || metadata == null || metadata.length == 0) return Optional.empty();
        final Document document;
        try { document = SecureXml.parse(metadata); }
        catch (SamlException invalid) { return Optional.empty(); }
        var evidence = List.of(new EvidenceRef("target-metadata", digest(metadata)));
        if (isAlgorithmPublicationCapability(caseId)) {
            return algorithmPublicationCapability(document, evidence);
        }
        if (idpSuffix(caseId, "f7") || suffix(caseId, "f8") || suffix(caseId, "fa")) {
            return publishedUiGuidance(caseId, document, evidence);
        }
        if (idpSuffix(caseId, "ae")) return uniquePublishedSigningKey(document, evidence);
        if (idpSuffix(caseId, "e5")) return encryptionPreferenceAntecedent(document, evidence);
        if (suffix(caseId, "a3")) return Optional.of(extensionNamespaces(document, evidence));
        if (suffix(caseId, "a6")) return Optional.of(rootOnlyExpiration(document, evidence));
        if (suffix(caseId, "a7")) return Optional.of(roleOverlap(document, evidence));
        if (suffix(caseId, "a9")) return Optional.of(saml2RoleProtocol(document, evidence));
        if (suffix(caseId, "ab")) return Optional.of(oneDirectionResponseLocation(document, evidence));
        if (suffix(caseId, "c8")) return keyDescriptorCardinality(document, evidence);
        if (suffix(caseId, "c9")) return Optional.of(keyInfoRepresentation(document, evidence));
        if (suffix(caseId, "ca")) return Optional.of(singleCertificate(document, evidence));
        if (suffix(caseId, "cb")) return Optional.of(coRepresentedKey(document, evidence));
        if (suffix(caseId, "cc")) return Optional.of(informationalKeyHints(document, evidence));
        if (suffix(caseId, "ce")) return certificateValidity(document, evidence, now);
        if (suffix(caseId, "d2")) return Optional.of(noAssertionsUnderEntitiesDescriptor(document, evidence));
        if (suffix(caseId, "d3")) return Optional.of(singleEntityAttributesPerExtensions(document, evidence));
        if (suffix(caseId, "d4")) return Optional.of(entityAttributeAssertionSubject(document, evidence));
        if (suffix(caseId, "d5")) return Optional.of(entityAttributeAssertionConfirmation(document, evidence));
        if (suffix(caseId, "d6")) return Optional.of(entityAttributeStatementCardinality(document, evidence));
        if (suffix(caseId, "d7")) return Optional.of(entityAttributeStatementTypes(document, evidence));
        if (suffix(caseId, "d8")) return entityAttributeAssertionSignature(document, evidence);
        if (suffix(caseId, "d9")) return Optional.of(informationalAssertionContent(document, evidence));
        if (suffix(caseId, "e1")) return Optional.of(encryptionAlgorithmCategories(document, evidence));
        if (suffix(caseId, "e2")) return encryptionKeyCompatibility(document, evidence);
        if (suffix(caseId, "e3")) return Optional.of(symmetricKeyAlgorithms(document, evidence));
        if (suffix(caseId, "e4")) return Optional.of(requiredAlgorithm(document, MD, "EncryptionMethod", evidence));
        if (suffix(caseId, "e6")) return Optional.of(publishedSignatureAlgorithms(document, evidence));
        if (suffix(caseId, "ec")) return Optional.of(requiredAlgorithmElements(document, evidence));
        if (suffix(caseId, "ed")) return Optional.of(informationalOtherEncryptionAlgorithms(document, evidence));
        if (suffix(caseId, "f1")) return Optional.of(uiInfoPlacement(document, evidence));
        if (suffix(caseId, "f2")) return Optional.of(nonEmptyUiContainer(
                document, "UIInfo", "metadata.publisher.ui-info-content", evidence));
        if (suffix(caseId, "f3")) return Optional.of(singlePerExtensions(
                document, "UIInfo", "metadata.publisher.ui-info-cardinality", evidence));
        if (suffix(caseId, "f4")) return Optional.of(localizedUiLanguages(document, evidence));
        if (idpSuffix(caseId, "fc")) return Optional.of(discoHintsPlacement(document, evidence));
        if (idpSuffix(caseId, "fd")) return Optional.of(nonEmptyUiContainer(
                document, "DiscoHints", "metadata.publisher.disco-hints-content", evidence));
        if (idpSuffix(caseId, "fe")) return Optional.of(singlePerExtensions(
                document, "DiscoHints", "metadata.publisher.disco-hints-cardinality", evidence));
        if (suffix(caseId, "fk")) return Optional.of(logoDimensions(document, evidence));
        return Optional.empty();
    }

    private static Optional<CaseOutcome> uniquePublishedSigningKey(Document document, List<EvidenceRef> evidence) {
        var root = document.getDocumentElement();
        if (!MD.equals(root.getNamespaceURI()) || !"EntityDescriptor".equals(root.getLocalName())) return Optional.empty();
        var roles = directElements(root, MD, "IDPSSODescriptor");
        if (roles.isEmpty()) return Optional.empty();
        var keys = new java.util.LinkedHashSet<String>();
        for (var role : roles) {
            boolean signingKeyFound = false;
            for (var descriptor : directElements(role, MD, "KeyDescriptor")) {
                var use = descriptor.getAttribute("use");
                if ("encryption".equals(use)) continue;
                if (!use.isEmpty() && !"signing".equals(use)) return Optional.empty();
                var infos = directElements(descriptor, DS, "KeyInfo");
                if (infos.size() != 1) return Optional.empty();
                var info = infos.getFirst();
                // Additional key representations need equality proof, not a guessed key count.
                for (var child = info.getFirstChild(); child != null; child = child.getNextSibling()) {
                    if (child instanceof Element element && (!DS.equals(element.getNamespaceURI())
                            || !Set.of("X509Data", "KeyName").contains(element.getLocalName()))) return Optional.empty();
                }
                var containers = directElements(info, DS, "X509Data");
                if (containers.size() != 1) return Optional.empty();
                for (var child = containers.getFirst().getFirstChild(); child != null; child = child.getNextSibling()) {
                    if (child instanceof Element element && (!DS.equals(element.getNamespaceURI())
                            || !"X509Certificate".equals(element.getLocalName()))) return Optional.empty();
                }
                var certificates = directElements(containers.getFirst(), DS, "X509Certificate");
                if (certificates.size() != 1) return Optional.empty();
                try { keys.add(Base64.getEncoder().encodeToString(certificate(certificates.getFirst()).getPublicKey().getEncoded())); }
                catch (IllegalArgumentException invalid) { return Optional.empty(); }
                signingKeyFound = true;
            }
            if (!signingKeyFound) return Optional.empty();
        }
        if (keys.size() != 1) return Optional.empty();
        return Optional.of(result(Outcome.SATISFIED_WITH_NOTE,
                "metadata.publisher.signing-key-unambiguous", evidence,
                Map.of("distinct_signing_keys", 1, "role", "IDPSSODescriptor")));
    }

    /** The approved e5 control explicitly satisfies zero/singleton groups; multiple choices still need execution. */
    private static Optional<CaseOutcome> encryptionPreferenceAntecedent(
            Document document, List<EvidenceRef> evidence) {
        var root = document.getDocumentElement();
        if (!MD.equals(root.getNamespaceURI()) || !"EntityDescriptor".equals(root.getLocalName())
                || root.getAttribute("entityID").isBlank()) return Optional.empty();
        var roles = directElements(root, MD, "IDPSSODescriptor");
        if (roles.isEmpty()) return Optional.empty();
        int descriptors = 0;
        for (var role : roles) {
            if (!List.of(role.getAttribute("protocolSupportEnumeration").split("\\s+")).contains(SAML2)) return Optional.empty();
            for (var key : directElements(role, MD, "KeyDescriptor")) {
                if ("signing".equals(key.getAttribute("use"))) continue;
                if (!key.getAttribute("use").isEmpty() && !"encryption".equals(key.getAttribute("use"))) return Optional.empty();
                descriptors++;
                int data = 0, transport = 0;
                for (var method : directElements(key, MD, "EncryptionMethod")) {
                    var algorithm = method.getAttribute("Algorithm");
                    if (DATA_ENCRYPTION.contains(algorithm)) data++;
                    else if (KEY_TRANSPORT_OR_AGREEMENT.contains(algorithm)) transport++;
                    else return Optional.empty(); // Unknown types cannot establish singleton groups.
                }
                if (data > 1 || transport > 1) return Optional.empty();
            }
        }
        return Optional.of(result(Outcome.SATISFIED, "metadata.publisher.encryption-preference-antecedent-false",
                evidence, Map.of("encryption_key_descriptors", descriptors,
                        "multiple_algorithms_of_same_type", false,
                        "scope", "published-metadata-snapshot")));
    }

    private static Optional<CaseOutcome> publishedUiGuidance(
            String caseId, Document document, List<EvidenceRef> evidence) {
        var root = document.getDocumentElement();
        if (!MD.equals(root.getNamespaceURI())
                || !Set.of("EntityDescriptor", "EntitiesDescriptor").contains(root.getLocalName())) return Optional.empty();
        var roleName = caseId.contains("-idp-") ? "IDPSSODescriptor" : "SPSSODescriptor";
        var roles = elements(document, MD, roleName);
        if (roles.isEmpty()) return Optional.empty();
        var elementName = idpSuffix(caseId, "f7") ? "Description" : suffix(caseId, "f8") ? "Logo" : "InformationURL";
        var published = new ArrayList<Element>();
        for (var role : roles) {
            var extensions = direct(role, MD, "Extensions");
            if (extensions == null) continue;
            // Only role UIInfo counts; Organization or another role's content cannot stand in.
            for (var info : elements(extensions, UI, "UIInfo")) {
                for (var child = info.getFirstChild(); child != null; child = child.getNextSibling()) {
                    if (child instanceof Element element && UI.equals(element.getNamespaceURI())
                            && elementName.equals(element.getLocalName())) published.add(element);
                }
            }
        }
        if (published.isEmpty()) return Optional.of(result(Outcome.SATISFIED_WITH_NOTE,
                "metadata.publisher.ui-guidance-not-published", evidence,
                Map.of("role", roleName, "element", elementName, "published_elements", 0)));
        if ("Logo".equals(elementName)) {
            var nonHttps = published.stream().map(Element::getTextContent).map(String::strip)
                    .filter(value -> {
                        try { return !"https".equalsIgnoreCase(java.net.URI.create(value).getScheme()); }
                        catch (IllegalArgumentException invalid) { return true; }
                    }).count();
            if (nonHttps > 0) return Optional.of(result(Outcome.VIOLATED,
                    "metadata.publisher.logo-https-guidance", evidence,
                    Map.of("published_elements", published.size(), "non_https_logos", nonHttps)));
        }
        // Natural-language usefulness, retrieved image format, and an appropriate background
        // require their actual evidence. URL suffixes and empty text are not absence proofs.
        return Optional.empty();
    }

    /**
     * A metadata document that publishes both signature and encryption algorithm declarations is
     * positive evidence of the MD09.a capability. Absence or a partial declaration is
     * inconclusive, never a violation: the target might be capable of publishing the declarations
     * in another runtime configuration.
     */
    private static Optional<CaseOutcome> algorithmPublicationCapability(
            Document document, List<EvidenceRef> evidence) {
        var signing = elements(document, ALG, "SigningMethod").stream()
                .filter(value -> !value.getAttribute("Algorithm").isBlank()).count();
        var encryption = elements(document, ALG, "EncryptionMethod").stream()
                .filter(value -> !value.getAttribute("Algorithm").isBlank()).count();
        if (signing == 0 || encryption == 0) return Optional.empty();
        return Optional.of(result(
                Outcome.SATISFIED, "metadata.publisher.algorithm-capability-published", evidence,
                Map.of("signing_methods", signing, "encryption_methods", encryption)));
    }

    private static CaseOutcome rootOnlyExpiration(Document document, List<EvidenceRef> evidence) {
        var root = document.getDocumentElement();
        var violations = new ArrayList<String>();
        var nodes = document.getElementsByTagNameNS(MD, "*");
        for (var index = 0; index < nodes.getLength(); index++) {
            var element = (Element) nodes.item(index);
            if (element != root && (element.hasAttribute("validUntil") || element.hasAttribute("cacheDuration"))) {
                violations.add(element.getTagName());
            }
        }
        return result(
                violations.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                "metadata.publisher.root-only-expiration", evidence,
                Map.of("root", root.getTagName(), "non_root_expiration_attributes", violations));
    }

    private static Optional<CaseOutcome> keyDescriptorCardinality(
            Document document, List<EvidenceRef> evidence) {
        var descriptors = elements(document, MD, "KeyDescriptor");
        var violations = new ArrayList<Integer>();
        var ambiguous = new ArrayList<Integer>();
        for (var index = 0; index < descriptors.size(); index++) {
            var keyInfo = direct(descriptors.get(index), DS, "KeyInfo");
            if (keyInfo == null) {
                violations.add(index);
                continue;
            }
            var keyValues = elements(keyInfo, DS, "KeyValue").size();
            var certificates = elements(keyInfo, DS, "X509Certificate").size();
            if (keyValues == 0 && certificates == 0) violations.add(index);
            else if (keyValues > 1 || certificates > 1) violations.add(index);
            else if (keyValues == 1 && certificates == 1) ambiguous.add(index);
        }
        if (!violations.isEmpty()) return Optional.of(result(
                Outcome.VIOLATED, "metadata.publisher.key-descriptor-cardinality", evidence,
                Map.of("descriptors", descriptors.size(), "invalid_descriptors", violations)));
        if (!ambiguous.isEmpty()) return Optional.empty();
        return Optional.of(result(
                descriptors.isEmpty() ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED,
                "metadata.publisher.key-descriptor-cardinality", evidence,
                Map.of("descriptors", descriptors.size())));
    }

    private static CaseOutcome coRepresentedKey(Document document, List<EvidenceRef> evidence) {
        var inspected = 0;
        var unresolved = new ArrayList<Integer>();
        var descriptors = elements(document, MD, "KeyDescriptor");
        for (var index = 0; index < descriptors.size(); index++) {
            var keyInfo = direct(descriptors.get(index), DS, "KeyInfo");
            if (keyInfo == null) continue;
            if (!elements(keyInfo, DS, "KeyValue").isEmpty()
                    && !elements(keyInfo, DS, "X509Certificate").isEmpty()) {
                inspected++;
                unresolved.add(index);
            }
        }
        if (!unresolved.isEmpty()) return new CaseOutcome(
                Outcome.NOT_VERIFIED, "co_represented_key_comparison_unavailable",
                "metadata.publisher.co-represented-key-unresolved",
                "metadata.publisher.co-represented-key-unresolved", evidence,
                Map.of("descriptors", inspected, "unresolved_descriptors", unresolved));
        return result(Outcome.SATISFIED_WITH_NOTE, "metadata.publisher.no-co-represented-keys", evidence,
                Map.of("descriptors", descriptors.size(), "co_represented", 0));
    }

    private static CaseOutcome informationalKeyHints(Document document, List<EvidenceRef> evidence) {
        var observed = keyDescriptorElements(document, DS, "KeyName").size()
                + keyDescriptorElements(document, DS, "X509SubjectName").size()
                + keyDescriptorElements(document, DS, "X509IssuerSerial").size();
        return result(Outcome.SATISFIED_WITH_NOTE, "metadata.publisher.key-hints-recorded", evidence,
                Map.of("observed_hints", observed));
    }

    private static CaseOutcome informationalAssertionContent(Document document, List<EvidenceRef> evidence) {
        var assertions = entityAttributeAssertions(document);
        var conditions = assertions.stream().mapToInt(value -> elements(value, ASSERTION, "Conditions").size()).sum();
        var advice = assertions.stream().mapToInt(value -> elements(value, ASSERTION, "Advice").size()).sum();
        return result(Outcome.SATISFIED_WITH_NOTE, "metadata.publisher.assertion-content-recorded", evidence,
                Map.of("assertions", assertions.size(), "conditions", conditions, "advice", advice));
    }

    private static Optional<CaseOutcome> encryptionKeyCompatibility(
            Document document, List<EvidenceRef> evidence) {
        var inspected = 0;
        var violations = new ArrayList<String>();
        var unresolved = new ArrayList<String>();
        for (var descriptor : elements(document, MD, "KeyDescriptor")) {
            var methods = directElements(descriptor, MD, "EncryptionMethod");
            if (methods.isEmpty()) continue;
            String keyType = null;
            var certificates = elements(descriptor, DS, "X509Certificate");
            if (certificates.size() == 1) {
                try { keyType = certificate(certificates.getFirst()).getPublicKey().getAlgorithm(); }
                catch (RuntimeException invalid) { unresolved.add("invalid-certificate"); }
            }
            for (var method : methods) {
                var algorithm = method.getAttribute("Algorithm");
                if (!KEY_TRANSPORT_OR_AGREEMENT.contains(algorithm)) continue;
                inspected++;
                if (keyType == null) unresolved.add(algorithm);
                else if (algorithm.contains("rsa-") && !"RSA".equalsIgnoreCase(keyType)) violations.add(algorithm);
                else if (algorithm.endsWith("ECDH-ES") && !"EC".equalsIgnoreCase(keyType)) violations.add(algorithm);
            }
        }
        if (!violations.isEmpty()) return Optional.of(result(
                Outcome.VIOLATED, "metadata.publisher.incompatible-key-algorithm", evidence,
                Map.of("inspected", inspected, "incompatible", violations)));
        if (!unresolved.isEmpty()) return Optional.empty();
        return Optional.of(result(
                inspected == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED,
                "metadata.publisher.key-algorithm-compatible", evidence, Map.of("inspected", inspected)));
    }

    private static CaseOutcome symmetricKeyAlgorithms(Document document, List<EvidenceRef> evidence) {
        var inspected = 0;
        var violations = new ArrayList<Integer>();
        var descriptors = elements(document, MD, "KeyDescriptor");
        for (var index = 0; index < descriptors.size(); index++) {
            var descriptor = descriptors.get(index);
            var keyInfo = direct(descriptor, DS, "KeyInfo");
            if (keyInfo == null || direct(keyInfo, DS, "KeyName") == null
                    || !elements(keyInfo, DS, "KeyValue").isEmpty()
                    || !elements(keyInfo, DS, "X509Certificate").isEmpty()) continue;
            inspected++;
            if (directElements(descriptor, MD, "EncryptionMethod").stream()
                    .noneMatch(value -> DATA_ENCRYPTION.contains(value.getAttribute("Algorithm")))) {
                violations.add(index);
            }
        }
        return result(
                !violations.isEmpty() ? Outcome.VIOLATED
                        : inspected == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED,
                "metadata.publisher.symmetric-key-algorithms", evidence,
                Map.of("symmetric_descriptors", inspected, "missing_data_algorithm", violations));
    }

    private static CaseOutcome informationalOtherEncryptionAlgorithms(
            Document document, List<EvidenceRef> evidence) {
        var other = elements(document, MD, "EncryptionMethod").stream()
                .map(value -> value.getAttribute("Algorithm"))
                .filter(value -> !DATA_ENCRYPTION.contains(value)
                        && !KEY_TRANSPORT_OR_AGREEMENT.contains(value))
                .toList();
        return result(Outcome.SATISFIED_WITH_NOTE, "metadata.publisher.other-encryption-algorithms-recorded",
                evidence, Map.of("algorithms", other));
    }

    private static CaseOutcome extensionNamespaces(Document document, List<EvidenceRef> evidence) {
        var extensionChildren = new ArrayList<Element>();
        for (var extensions : elements(document, MD, "Extensions")) {
            extensionChildren.addAll(directElements(extensions));
        }
        var violations = new ArrayList<String>();
        for (var child : extensionChildren) {
            var namespace = child.getNamespaceURI();
            if (namespace == null || namespace.isBlank()
                    || MD.equals(namespace) || ASSERTION.equals(namespace) || PROTOCOL.equals(namespace)) {
                violations.add(child.getTagName());
            }
        }
        return conditionalResult(
                extensionChildren.size(), violations, "metadata.publisher.extension-namespace", evidence,
                Map.of("extension_elements", extensionChildren.size(), "invalid_elements", violations));
    }

    private static CaseOutcome noAssertionsUnderEntitiesDescriptor(
            Document document, List<EvidenceRef> evidence) {
        var containers = elements(document, MDATTR, "EntityAttributes");
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < containers.size(); index++) {
            var owner = metadataExtensionOwner(containers.get(index));
            if (owner != null && "EntitiesDescriptor".equals(owner.getLocalName())
                    && !elements(containers.get(index), ASSERTION, "Assertion").isEmpty()) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                containers.size(), invalid, "metadata.publisher.entity-attributes-entities-assertion", evidence,
                Map.of("entity_attributes", containers.size(), "invalid_containers", invalid));
    }

    private static CaseOutcome singleEntityAttributesPerExtensions(
            Document document, List<EvidenceRef> evidence) {
        var observed = elements(document, MDATTR, "EntityAttributes").size();
        var invalid = new ArrayList<Integer>();
        var extensions = elements(document, MD, "Extensions");
        for (var index = 0; index < extensions.size(); index++) {
            if (directElements(extensions.get(index), MDATTR, "EntityAttributes").size() > 1) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                observed, invalid, "metadata.publisher.entity-attributes-cardinality", evidence,
                Map.of("entity_attributes", observed, "extensions_with_duplicates", invalid));
    }

    private static CaseOutcome entityAttributeAssertionSubject(
            Document document, List<EvidenceRef> evidence) {
        var assertions = entityAttributeAssertions(document);
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < assertions.size(); index++) {
            var assertion = assertions.get(index);
            var entity = metadataExtensionOwner(assertion);
            var subject = direct(assertion, ASSERTION, "Subject");
            var nameId = subject == null ? null : direct(subject, ASSERTION, "NameID");
            if (entity == null || !"EntityDescriptor".equals(entity.getLocalName())
                    || nameId == null
                    || !"urn:oasis:names:tc:SAML:2.0:nameid-format:entity".equals(nameId.getAttribute("Format"))
                    || !entity.getAttribute("entityID").equals(nameId.getTextContent())) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                assertions.size(), invalid, "metadata.publisher.entity-attributes-subject", evidence,
                Map.of("assertions", assertions.size(), "invalid_assertions", invalid));
    }

    private static CaseOutcome entityAttributeAssertionConfirmation(
            Document document, List<EvidenceRef> evidence) {
        var assertions = entityAttributeAssertions(document);
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < assertions.size(); index++) {
            if (!elements(assertions.get(index), ASSERTION, "SubjectConfirmation").isEmpty()) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                assertions.size(), invalid, "metadata.publisher.entity-attributes-subject-confirmation", evidence,
                Map.of("assertions", assertions.size(), "invalid_assertions", invalid));
    }

    private static CaseOutcome entityAttributeStatementCardinality(
            Document document, List<EvidenceRef> evidence) {
        var assertions = entityAttributeAssertions(document);
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < assertions.size(); index++) {
            if (directElements(assertions.get(index), ASSERTION, "AttributeStatement").size() != 1) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                assertions.size(), invalid, "metadata.publisher.entity-attributes-statement-cardinality", evidence,
                Map.of("assertions", assertions.size(), "invalid_assertions", invalid));
    }

    private static CaseOutcome entityAttributeStatementTypes(
            Document document, List<EvidenceRef> evidence) {
        var assertions = entityAttributeAssertions(document);
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < assertions.size(); index++) {
            var otherStatement = directElements(assertions.get(index)).stream()
                    .anyMatch(value -> ASSERTION.equals(value.getNamespaceURI())
                            && ("Statement".equals(value.getLocalName())
                            || (value.getLocalName().endsWith("Statement")
                            && !"AttributeStatement".equals(value.getLocalName()))));
            if (otherStatement) invalid.add(index);
        }
        return conditionalResult(
                assertions.size(), invalid, "metadata.publisher.entity-attributes-statement-types", evidence,
                Map.of("assertions", assertions.size(), "invalid_assertions", invalid));
    }

    private static Optional<CaseOutcome> entityAttributeAssertionSignature(
            Document document, List<EvidenceRef> evidence) {
        var assertions = entityAttributeAssertions(document);
        if (assertions.isEmpty()) {
            return Optional.of(result(
                    Outcome.SATISFIED_WITH_NOTE, "metadata.publisher.no-entity-attribute-assertions",
                    evidence, Map.of("assertions", 0)));
        }
        var unsigned = new ArrayList<Integer>();
        for (var index = 0; index < assertions.size(); index++) {
            if (direct(assertions.get(index), DS, "Signature") == null) unsigned.add(index);
        }
        if (!unsigned.isEmpty()) {
            return Optional.of(result(
                    Outcome.VIOLATED, "metadata.publisher.entity-attributes-assertion-unsigned",
                    evidence, Map.of("assertions", assertions.size(), "unsigned", unsigned)));
        }
        // Presence alone does not prove cryptographic validity. Keep signed instances on the
        // approved evidence path until a signature-verification oracle is available.
        return Optional.empty();
    }

    private static List<Element> entityAttributeAssertions(Document document) {
        var result = new ArrayList<Element>();
        for (var container : elements(document, MDATTR, "EntityAttributes")) {
            result.addAll(directElements(container, ASSERTION, "Assertion"));
        }
        return List.copyOf(result);
    }

    private static Element metadataExtensionOwner(Element element) {
        for (var current = parent(element); current != null; current = parent(current)) {
            if (MD.equals(current.getNamespaceURI())
                    && ("EntityDescriptor".equals(current.getLocalName())
                    || "EntitiesDescriptor".equals(current.getLocalName()))) {
                return current;
            }
        }
        return null;
    }

    private static CaseOutcome roleOverlap(Document document, List<EvidenceRef> evidence) {
        var inspected = 0;
        var violations = new ArrayList<String>();
        for (var entity : elements(document, MD, "EntityDescriptor")) {
            var byType = new java.util.LinkedHashMap<String, List<Element>>();
            for (var child = entity.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child instanceof Element role && MD.equals(role.getNamespaceURI())
                        && ROLE_ELEMENTS.contains(role.getLocalName())) {
                    byType.computeIfAbsent(roleType(role), ignored -> new ArrayList<>()).add(role);
                }
            }
            for (var entry : byType.entrySet()) {
                if (entry.getValue().size() < 2) continue;
                inspected += entry.getValue().size();
                var seen = new HashSet<String>();
                for (var role : entry.getValue()) {
                    for (var protocol : tokens(role.getAttribute("protocolSupportEnumeration"))) {
                        if (!seen.add(protocol)) violations.add(entry.getKey() + ":" + protocol);
                    }
                }
            }
        }
        return result(
                violations.isEmpty() ? (inspected == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.role-protocol-overlap", evidence,
                Map.of("compared_roles", inspected, "overlaps", violations));
    }

    private static CaseOutcome saml2RoleProtocol(Document document, List<EvidenceRef> evidence) {
        var roles = new ArrayList<Element>();
        for (var role : CONCRETE_SAML_ROLE_ELEMENTS) roles.addAll(elements(document, MD, role));
        var violations = roles.stream()
                .filter(role -> !tokens(role.getAttribute("protocolSupportEnumeration")).contains(SAML2))
                .map(Element::getLocalName).toList();
        return result(
                violations.isEmpty() ? (roles.isEmpty() ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.saml2-role-protocol", evidence,
                Map.of("roles", roles.size(), "missing_protocol", violations));
    }

    private static CaseOutcome oneDirectionResponseLocation(Document document, List<EvidenceRef> evidence) {
        var observed = 0;
        var violations = new ArrayList<String>();
        for (var localName : ONE_DIRECTION_ENDPOINTS) {
            for (var endpoint : elements(document, MD, localName)) {
                observed++;
                if (endpoint.hasAttribute("ResponseLocation")) violations.add(localName);
            }
        }
        return result(
                violations.isEmpty() ? (observed == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.one-direction-response-location", evidence,
                Map.of("endpoints", observed, "violations", violations));
    }

    private static CaseOutcome keyInfoRepresentation(Document document, List<EvidenceRef> evidence) {
        var descriptors = elements(document, MD, "KeyDescriptor");
        var violations = new ArrayList<Integer>();
        for (var index = 0; index < descriptors.size(); index++) {
            var keyInfo = direct(descriptors.get(index), DS, "KeyInfo");
            var keyValues = keyInfo == null ? 0 : keyInfo.getElementsByTagNameNS(DS, "KeyValue").getLength();
            var certificates = keyInfo == null ? 0 : keyInfo.getElementsByTagNameNS(DS, "X509Certificate").getLength();
            if (keyValues == 0 && certificates != 1) violations.add(index);
        }
        return result(
                violations.isEmpty() ? (descriptors.isEmpty() ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.key-representation", evidence,
                Map.of("key_descriptors", descriptors.size(), "violations", violations));
    }

    private static CaseOutcome singleCertificate(Document document, List<EvidenceRef> evidence) {
        var data = keyDescriptorElements(document, DS, "X509Data");
        var violations = new ArrayList<Integer>();
        var observed = 0;
        for (var index = 0; index < data.size(); index++) {
            var count = data.get(index).getElementsByTagNameNS(DS, "X509Certificate").getLength();
            if (count == 0) continue;
            observed++;
            if (count != 1) violations.add(index);
        }
        return result(
                violations.isEmpty() ? (observed == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.single-certificate", evidence,
                Map.of("x509_representations", observed, "violations", violations));
    }

    private static Optional<CaseOutcome> certificateValidity(
            Document document, List<EvidenceRef> evidence, Instant now) {
        var certificates = keyDescriptorElements(document, DS, "X509Certificate");
        if (certificates.isEmpty()) {
            return Optional.of(result(Outcome.SATISFIED_WITH_NOTE,
                    "metadata.publisher.no-certificates", evidence, Map.of("certificates", 0)));
        }
        var invalid = new ArrayList<Integer>();
        try {
            var factory = CertificateFactory.getInstance("X.509");
            for (var index = 0; index < certificates.size(); index++) {
                var encoded = certificates.get(index).getTextContent().replaceAll("\\s+", "");
                var certificate = (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
                if (now.isAfter(certificate.getNotAfter().toInstant())) invalid.add(index);
            }
        } catch (Exception unparseable) {
            return Optional.empty();
        }
        return Optional.of(result(
                invalid.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                "metadata.publisher.certificate-validity", evidence,
                Map.of("certificates", certificates.size(), "not_currently_valid", invalid)));
    }

    private static CaseOutcome encryptionAlgorithmCategories(Document document, List<EvidenceRef> evidence) {
        var descriptors = elements(document, MD, "KeyDescriptor").stream()
                // An omitted @use means the key may be used for both signing and encryption.
                .filter(value -> !"signing".equals(value.getAttribute("use")))
                .toList();
        var violations = new ArrayList<Integer>();
        for (var index = 0; index < descriptors.size(); index++) {
            var algorithms = elements(descriptors.get(index), MD, "EncryptionMethod").stream()
                    .map(value -> value.getAttribute("Algorithm")).collect(java.util.stream.Collectors.toSet());
            if (algorithms.stream().noneMatch(DATA_ENCRYPTION::contains)
                    || algorithms.stream().noneMatch(KEY_TRANSPORT_OR_AGREEMENT::contains)) {
                violations.add(index);
            }
        }
        return result(
                violations.isEmpty() ? (descriptors.isEmpty() ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.encryption-algorithm-categories", evidence,
                Map.of("encryption_key_descriptors", descriptors.size(), "violations", violations));
    }

    private static CaseOutcome requiredAlgorithm(
            Document document, String namespace, String localName, List<EvidenceRef> evidence) {
        var methods = elements(document, namespace, localName);
        var violations = methods.stream().filter(value -> value.getAttribute("Algorithm").isBlank()).count();
        return result(
                violations == 0 ? (methods.isEmpty() ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.required-algorithm", evidence,
                Map.of("elements", methods.size(), "missing_algorithm", violations));
    }

    private static CaseOutcome publishedSignatureAlgorithms(Document document, List<EvidenceRef> evidence) {
        var entities = elements(document, MD, "EntityDescriptor");
        var missing = new ArrayList<Integer>();
        var digests = 0;
        var signatures = 0;
        for (var index = 0; index < entities.size(); index++) {
            var entityDigests = elements(entities.get(index), ALG, "DigestMethod").size();
            var entitySignatures = elements(entities.get(index), ALG, "SigningMethod").size();
            digests += entityDigests;
            signatures += entitySignatures;
            if (entityDigests == 0 || entitySignatures == 0) missing.add(index);
        }
        return result(
                !entities.isEmpty() && missing.isEmpty() ? Outcome.SATISFIED : Outcome.VIOLATED,
                "metadata.publisher.signature-algorithm-capabilities", evidence,
                Map.of(
                        "entities", entities.size(),
                        "digest_methods", digests,
                        "signing_methods", signatures,
                        "entities_missing_capabilities", missing));
    }

    private static CaseOutcome requiredAlgorithmElements(Document document, List<EvidenceRef> evidence) {
        var elements = new ArrayList<Element>();
        elements.addAll(elements(document, ALG, "DigestMethod"));
        elements.addAll(elements(document, ALG, "SigningMethod"));
        var violations = elements.stream().filter(value -> value.getAttribute("Algorithm").isBlank()).count();
        return result(
                violations == 0 ? (elements.isEmpty() ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED)
                        : Outcome.VIOLATED,
                "metadata.publisher.algorithm-support-uri", evidence,
                Map.of("elements", elements.size(), "missing_algorithm", violations));
    }

    private static CaseOutcome uiInfoPlacement(Document document, List<EvidenceRef> evidence) {
        var uiInfo = elements(document, UI, "UIInfo");
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < uiInfo.size(); index++) {
            var extensions = parent(uiInfo.get(index));
            var role = extensions == null ? null : parent(extensions);
            if (extensions == null || !MD.equals(extensions.getNamespaceURI())
                    || !"Extensions".equals(extensions.getLocalName())
                    || role == null || !MD.equals(role.getNamespaceURI())
                    || !ROLE_ELEMENTS.contains(role.getLocalName())) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                uiInfo.size(), invalid, "metadata.publisher.ui-info-placement", evidence,
                Map.of("ui_info", uiInfo.size(), "invalid_placement", invalid));
    }

    private static CaseOutcome discoHintsPlacement(Document document, List<EvidenceRef> evidence) {
        var hints = elements(document, UI, "DiscoHints");
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < hints.size(); index++) {
            var extensions = parent(hints.get(index));
            var role = extensions == null ? null : parent(extensions);
            if (extensions == null || !MD.equals(extensions.getNamespaceURI())
                    || !"Extensions".equals(extensions.getLocalName())
                    || role == null || !MD.equals(role.getNamespaceURI())
                    || !"IDPSSODescriptor".equals(role.getLocalName())) {
                invalid.add(index);
            }
        }
        return conditionalResult(
                hints.size(), invalid, "metadata.publisher.disco-hints-placement", evidence,
                Map.of("disco_hints", hints.size(), "invalid_placement", invalid));
    }

    private static CaseOutcome nonEmptyUiContainer(
            Document document, String localName, String code, List<EvidenceRef> evidence) {
        var containers = elements(document, UI, localName);
        var empty = new ArrayList<Integer>();
        for (var index = 0; index < containers.size(); index++) {
            if (directElements(containers.get(index)).isEmpty()) empty.add(index);
        }
        return conditionalResult(
                containers.size(), empty, code, evidence,
                Map.of("containers", containers.size(), "empty", empty));
    }

    private static CaseOutcome singlePerExtensions(
            Document document, String localName, String code, List<EvidenceRef> evidence) {
        var observed = elements(document, UI, localName).size();
        var invalid = new ArrayList<Integer>();
        var extensions = elements(document, MD, "Extensions");
        for (var index = 0; index < extensions.size(); index++) {
            if (directElements(extensions.get(index), UI, localName).size() > 1) invalid.add(index);
        }
        return conditionalResult(
                observed, invalid, code, evidence,
                Map.of("elements", observed, "extensions_with_duplicates", invalid));
    }

    private static CaseOutcome localizedUiLanguages(Document document, List<EvidenceRef> evidence) {
        var uiInfo = elements(document, UI, "UIInfo");
        var localized = 0;
        var duplicates = new ArrayList<String>();
        var languagesByRole = new java.util.IdentityHashMap<Element, Map<String, Set<String>>>();
        for (var index = 0; index < uiInfo.size(); index++) {
            var container = uiInfo.get(index);
            var extensions = parent(container);
            var role = extensions == null ? null : parent(extensions);
            if (extensions == null || !MD.equals(extensions.getNamespaceURI())
                    || !"Extensions".equals(extensions.getLocalName())
                    || role == null || !MD.equals(role.getNamespaceURI())
                    || !ROLE_ELEMENTS.contains(role.getLocalName())) {
                continue; // The dedicated placement rule owns unscoped UIInfo containers.
            }
            var languages = languagesByRole.computeIfAbsent(
                    role, ignored -> new java.util.LinkedHashMap<>());
            for (var child : directElements(container)) {
                if (!UI.equals(child.getNamespaceURI())
                        || !LOCALIZED_UI_ELEMENTS.contains(child.getLocalName())) continue;
                localized++;
                var language = child.getAttributeNS(XMLConstants.XML_NS_URI, "lang")
                        .toLowerCase(java.util.Locale.ROOT);
                var seen = languages.computeIfAbsent(child.getLocalName(), ignored -> new HashSet<>());
                if (!seen.add(language)) duplicates.add(index + ":" + child.getLocalName() + ":" + language);
            }
        }
        return conditionalResult(
                localized, duplicates, "metadata.publisher.ui-info-languages", evidence,
                Map.of("localized_elements", localized, "duplicates", duplicates));
    }

    private static CaseOutcome logoDimensions(Document document, List<EvidenceRef> evidence) {
        var logos = elements(document, UI, "Logo");
        var invalid = new ArrayList<Integer>();
        for (var index = 0; index < logos.size(); index++) {
            var logo = logos.get(index);
            if (!logo.hasAttribute("height") || !logo.hasAttribute("width")) invalid.add(index);
        }
        return conditionalResult(
                logos.size(), invalid, "metadata.publisher.logo-dimensions", evidence,
                Map.of("logos", logos.size(), "missing_dimensions", invalid));
    }

    private static CaseOutcome conditionalResult(
            int observed, List<?> violations, String code,
            List<EvidenceRef> evidence, Map<String, Object> details) {
        var outcome = !violations.isEmpty()
                ? Outcome.VIOLATED
                : observed == 0 ? Outcome.SATISFIED_WITH_NOTE : Outcome.SATISFIED;
        return result(outcome, code, evidence, details);
    }

    private static boolean suffix(String caseId, String suffix) {
        return caseId.startsWith("IIP-MD05-" + suffix + "-")
                && (caseId.endsWith("-idp-01") || caseId.endsWith("-sp-01"));
    }

    private static boolean isAlgorithmPublicationCapability(String caseId) {
        return caseId.equals("IIP-MD09-a-idp-01") || caseId.equals("IIP-MD09-a-sp-01");
    }

    private static boolean idpSuffix(String caseId, String suffix) {
        return caseId.equals("IIP-MD05-" + suffix + "-idp-01");
    }

    private static List<Element> roleElements(Document document) {
        var result = new ArrayList<Element>();
        for (var role : ROLE_ELEMENTS) result.addAll(elements(document, MD, role));
        return result;
    }

    private static String roleType(Element role) {
        if (!"RoleDescriptor".equals(role.getLocalName())) return role.getLocalName();
        var lexical = role.getAttributeNS(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "type");
        if (lexical.isBlank()) return "RoleDescriptor#untyped";
        var separator = lexical.indexOf(':');
        var prefix = separator < 0 ? null : lexical.substring(0, separator);
        var localName = separator < 0 ? lexical : lexical.substring(separator + 1);
        var namespace = role.lookupNamespaceURI(prefix);
        return namespace == null ? lexical : "{" + namespace + "}" + localName;
    }

    private static List<Element> keyDescriptorElements(
            Document document, String namespace, String localName) {
        var result = new ArrayList<Element>();
        for (var descriptor : elements(document, MD, "KeyDescriptor")) {
            var keyInfo = direct(descriptor, DS, "KeyInfo");
            if (keyInfo != null) result.addAll(elements(keyInfo, namespace, localName));
        }
        return result;
    }

    private static X509Certificate certificate(Element element) {
        try {
            var encoded = element.getTextContent().replaceAll("\\s+", "");
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        } catch (Exception invalid) {
            throw new IllegalArgumentException("Invalid metadata certificate", invalid);
        }
    }

    private static List<Element> elements(Document document, String namespace, String localName) {
        var nodes = document.getElementsByTagNameNS(namespace, localName);
        var result = new ArrayList<Element>();
        for (var index = 0; index < nodes.getLength(); index++) result.add((Element) nodes.item(index));
        return result;
    }

    private static List<Element> elements(Element parent, String namespace, String localName) {
        var nodes = parent.getElementsByTagNameNS(namespace, localName);
        var result = new ArrayList<Element>();
        for (var index = 0; index < nodes.getLength(); index++) result.add((Element) nodes.item(index));
        return result;
    }

    private static Element direct(Element parent, String namespace, String localName) {
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) return element;
        }
        return null;
    }

    private static Element parent(Element element) {
        return element.getParentNode() instanceof Element parent ? parent : null;
    }

    private static List<Element> directElements(Element parent) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element) result.add(element);
        }
        return result;
    }

    private static List<Element> directElements(Element parent, String namespace, String localName) {
        return directElements(parent).stream()
                .filter(value -> namespace.equals(value.getNamespaceURI())
                        && localName.equals(value.getLocalName()))
                .toList();
    }

    private static Set<String> tokens(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return Set.copyOf(new HashSet<>(List.of(value.trim().split("\\s+"))));
    }

    private static CaseOutcome result(
            Outcome outcome, String code, List<EvidenceRef> evidence, Map<String, Object> details) {
        return new CaseOutcome(outcome, null, code, code, evidence, details);
    }

    private static String digest(byte[] value) {
        try {
            return "sha256:" + HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
