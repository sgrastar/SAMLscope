package com.samlscope.runner.cases;

import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;

/**
 * Producer-side XML Encryption algorithm observation for IIP-ALG04/ALG06 IdP cases.
 * A result is conclusive only from a decrypted, correlated EncryptedAssertion in a
 * successful Response; published metadata algorithm names are never used as evidence.
 */
final class EncryptionAlgorithmObservation {
    static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
    static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";
    static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String AES128_GCM = XENC11 + "aes128-gcm";
    static final String AES256_GCM = XENC11 + "aes256-gcm";
    static final String OAEP_MGF1P = XENC + "rsa-oaep-mgf1p";
    static final String OAEP = XENC11 + "rsa-oaep";
    static final String SHA1 = DS + "sha1";
    static final String SHA256 = XENC + "sha256";
    static final String MGF1_SHA1 = XENC11 + "mgf1sha1";
    static final String MGF1_SHA256 = XENC11 + "mgf1sha256";
    private static final String ALG04_A = "IIP-ALG04-a-idp-01";
    private static final String ALG04_B = "IIP-ALG04-b-idp-01";
    private static final String ALG06_A = "IIP-ALG06-a-idp-01";
    private static final String ALG06_B = "IIP-ALG06-b-idp-01";
    private static final String ALG06_C = "IIP-ALG06-c-idp-01";
    private static final String ALG06_D = "IIP-ALG06-d-idp-01";

    record Observation(EvidenceRef request, EvidenceRef response, String contentAlgorithm,
            String transportAlgorithm, String digestAlgorithm, String mgfAlgorithm, boolean decrypted) {
        Observation {
            Objects.requireNonNull(request, "request");
            Objects.requireNonNull(response, "response");
        }
    }

    private EncryptionAlgorithmObservation() {}

    static boolean supports(String caseId) {
        return List.of(ALG04_A, ALG04_B, ALG06_A, ALG06_B, ALG06_C, ALG06_D).contains(caseId);
    }

    static Optional<CaseOutcome> evaluate(String caseId, List<Observation> observations) {
        var decrypted = observations.stream().filter(Observation::decrypted).toList();
        if (decrypted.isEmpty()) return Optional.empty();
        return switch (caseId) {
            case ALG04_A -> observed(decrypted, AES128_GCM, "browser.encryption.aes128-gcm.decrypted");
            case ALG04_B -> observed(decrypted, AES256_GCM, "browser.encryption.aes256-gcm.decrypted");
            case ALG06_A -> observed(decrypted, OAEP_MGF1P, "browser.encryption.rsa-oaep-mgf1p.decrypted");
            case ALG06_B -> observed(decrypted, OAEP, "browser.encryption.rsa-oaep.decrypted");
            case ALG06_C -> digestCombinations(decrypted);
            case ALG06_D -> defaultMgfOaep(decrypted)
                    ? Optional.of(outcome(decrypted, "browser.encryption.mgf1-sha1-default.decrypted"))
                    : Optional.empty();
            default -> Optional.empty();
        };
    }

    /** Conclusive only when a decrypted assertion reports the required content or key transport algorithm. */
    private static Optional<CaseOutcome> observed(
            List<Observation> observations, String algorithm, String reason) {
        var matched = observations.stream().anyMatch(value ->
                algorithm.equals(value.contentAlgorithm()) || algorithm.equals(value.transportAlgorithm()));
        return matched ? Optional.of(outcome(observations, reason)) : Optional.empty();
    }

    private static boolean defaultMgfOaep(List<Observation> observations) {
        return observations.stream().anyMatch(EncryptionAlgorithmObservation::defaultMgfOaep);
    }

    private static Optional<CaseOutcome> digestCombinations(List<Observation> observations) {
        var combos = new HashSet<String>();
        for (var observation : observations) combos.add(digestCombo(observation));
        if (!combos.containsAll(List.of("rsa-oaep-mgf1p|sha1", "rsa-oaep-mgf1p|sha256",
                "rsa-oaep|sha1", "rsa-oaep|sha256"))) return Optional.empty();
        return Optional.of(outcome(observations, "browser.encryption.digest-combinations.decrypted"));
    }

    private static String digestCombo(Observation observation) {
        var transport = OAEP_MGF1P.equals(observation.transportAlgorithm()) ? "rsa-oaep-mgf1p"
                : OAEP.equals(observation.transportAlgorithm()) ? "rsa-oaep" : "other";
        // XML Encryption defaults an omitted DigestMethod to SHA-1; only explicitly
        // unsupported digest URIs are excluded from the approved combinations.
        var digest = observation.digestAlgorithm() == null || SHA1.equals(observation.digestAlgorithm())
                ? "sha1" : SHA256.equals(observation.digestAlgorithm()) ? "sha256" : "other";
        return transport + "|" + digest;
    }

    private static boolean defaultMgfOaep(Observation observation) {
        if (!OAEP.equals(observation.transportAlgorithm())) return false;
        var mgf = observation.mgfAlgorithm();
        return mgf == null || MGF1_SHA1.equals(mgf);
    }

    private static CaseOutcome outcome(List<Observation> observations, String reason) {
        var evidence = observations.stream()
                .flatMap(value -> java.util.stream.Stream.of(value.request(), value.response()))
                .distinct().toList();
        var content = new LinkedHashSet<String>();
        var transport = new LinkedHashSet<String>();
        var digest = new LinkedHashSet<String>();
        var mgf = new LinkedHashSet<String>();
        for (var observation : observations) {
            if (observation.contentAlgorithm() != null) content.add(observation.contentAlgorithm());
            if (observation.transportAlgorithm() != null) transport.add(observation.transportAlgorithm());
            if (observation.digestAlgorithm() != null) digest.add(observation.digestAlgorithm());
            if (observation.mgfAlgorithm() != null) mgf.add(observation.mgfAlgorithm());
        }
        var details = new LinkedHashMap<String, Object>();
        details.put("encryption_algorithm", List.copyOf(content));
        details.put("key_transport_algorithm", List.copyOf(transport));
        details.put("digest_algorithm", List.copyOf(digest));
        details.put("mgf_algorithm", List.copyOf(mgf));
        details.put("decrypted_assertions", observations.size());
        return new CaseOutcome(Outcome.SATISFIED, null, reason, reason, evidence, Map.copyOf(details));
    }

    /** Reads the encryption structure of a decrypted EncryptedAssertion wrapper. */
    static Observation inspect(EvidenceRef request, EvidenceRef response, Element wrapper, boolean decrypted) {
        var data = first(wrapper, XENC, "EncryptedData");
        var key = first(wrapper, XENC, "EncryptedKey");
        return new Observation(request, response,
                methodAlgorithm(data), methodAlgorithm(key),
                attribute(first(key, DS, "DigestMethod"), "Algorithm"),
                attribute(first(key, XENC11, "MGF"), "Algorithm"), decrypted);
    }

    private static String methodAlgorithm(Element parent) {
        return attribute(first(parent, XENC, "EncryptionMethod"), "Algorithm");
    }

    private static Element first(Element parent, String namespace, String localName) {
        if (parent == null) return null;
        var values = parent.getElementsByTagNameNS(namespace, localName);
        return values.getLength() == 0 ? null : (Element) values.item(0);
    }

    private static String attribute(Element element, String name) {
        if (element == null || !element.hasAttribute(name)) return null;
        var value = element.getAttribute(name);
        return value.isBlank() ? null : value;
    }
}
