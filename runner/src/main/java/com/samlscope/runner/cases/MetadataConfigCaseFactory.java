package com.samlscope.runner.cases;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.runner.cases.MetadataFixtureObservationTestCase.Behavior;
import com.samlscope.runner.cases.MetadataFixtureObservationTestCase.Fixture;

/** Product-neutral metadata fixture implementations for approved M2 CONFIG cases. */
final class MetadataConfigCaseFactory {
    private static final Map<String, List<Fixture>> FIXTURES = Map.ofEntries(
            Map.entry("IIP-MD02.b", List.of(
                    accept("redirect-301", "follow HTTP 301"),
                    accept("redirect-302", "follow HTTP 302"),
                    accept("redirect-307", "follow HTTP 307"))),
            Map.entry("IIP-MD02.c", List.of(
                    accept("entity-root", "consume an EntityDescriptor root"),
                    accept("entities-root-one", "consume an EntitiesDescriptor root"))),
            Map.entry("IIP-MD02.d", List.of(
                    accept("entities-root-one", "consume one child"),
                    accept("entities-root-two", "find the tested entity after another child"),
                    accept("entities-root-fifty", "find the tested entity after forty-nine children"))),
            Map.entry("IIP-MD03.a", List.of(
                    reject("unsigned", "reject unsigned metadata"),
                    reject("bad-signature", "reject metadata whose root signature no longer verifies"),
                    reject("signed-other-key", "reject metadata signed by an untrusted key"))),
            Map.entry("IIP-MD03.b", List.of(
                    accept("signed-other-key-primary-keyinfo",
                            "verify with the separately configured key rather than the certificate embedded in metadata"))),
            Map.entry("IIP-MD03.c", List.of(
                    accept("certificate-expired", "ignore certificate expiration when using the contained key"),
                    accept("certificate-not-yet-valid", "ignore certificate notBefore when using the contained key"),
                    accept("certificate-no-digital-signature", "ignore an incompatible KeyUsage flag"),
                    accept("certificate-critical-extension", "ignore certificate extensions when using the contained key"))),
            Map.entry("IIP-MD04.a", List.of(
                    reject("no-valid-until", "reject a root without validUntil in the enabled policy state"))),
            Map.entry("IIP-MD04.b", List.of(
                    reject("expired", "reject a root whose validUntil is in the past"))),
            Map.entry("IIP-MD04.c", List.of(
                    accept("valid-until-near", "accept a root whose validUntil is within the configured limit"),
                    reject("valid-until-far", "reject a root whose validUntil exceeds the configured limit"))),
            Map.entry("IIP-MD05.c", List.of(
                    accept("entity-root", "consume an MDIOP EntityDescriptor root"),
                    accept("entities-root-one", "consume an MDIOP EntitiesDescriptor root"),
                    accept("keyvalue-only", "consume a ds:KeyValue-only KeyDescriptor"),
                    accept("certificate-expired", "consume an expired certificate representation"),
                    accept("certificate-not-yet-valid", "consume a not-yet-valid certificate representation"),
                    accept("multiple-signing-keys-first", "consume the first of multiple signing keys"),
                    accept("multiple-signing-keys", "consume the second of multiple signing keys"))),
            Map.entry("IIP-MD05.a1", List.of(
                    accept("distinct-entity-ids", "consume distinct entityIDs in one deployment"),
                    reject("duplicate-entity-ids", "reject or surface a duplicate entityID conflict"))),
            Map.entry("IIP-MD05.a2", List.of(
                    accept("distinct-entity-ids", "consume the distinct-entity control"),
                    reject("conflicting-duplicate-entity-ids",
                            "reject duplicate entityIDs that advertise conflicting keys or endpoints"))),
            Map.entry("IIP-MD05.a3", List.of(
                    accept("unknown-extension", "consume an entity-level extension from a non-SAML namespace"),
                    accept("unknown-role-extension", "consume a role-level extension from a non-SAML namespace"),
                    accept("unknown-endpoint-extension", "consume endpoint extensions from a non-SAML namespace"),
                    accept("unknown-organization-extension", "consume an Organization extension from a non-SAML namespace"),
                    accept("unknown-contact-extension", "consume a ContactPerson extension from a non-SAML namespace"),
                    accept("unknown-affiliation-extension", "consume an AffiliationDescriptor extension from a non-SAML namespace"),
                    reject("invalid-organization-saml-extension", "reject a SAML-defined element in Organization/Extensions"))),
            Map.entry("IIP-MD05.a4", List.of(
                    accept("entity-root", "consume the single-entity root"),
                    accept("entities-root-one", "consume the multiple-entity root"))),
            Map.entry("IIP-MD05.a5", List.of(
                    accept("entity-cache-duration", "consume EntityDescriptor with cacheDuration only"),
                    accept("entities-cache-duration", "consume EntitiesDescriptor with cacheDuration only"),
                    accept("entity-root", "consume EntityDescriptor with validUntil"),
                    accept("entities-valid-until", "consume EntitiesDescriptor with validUntil"))),
            Map.entry("IIP-MD05.as", List.of(
                    reject("expired", "do not use endpoints or keys from expired metadata"))),
            Map.entry("IIP-MD05.g", List.of(
                    accept("unknown-extension", "ignore a well-formed unknown extension without failure"),
                    accept("mdrpi-registration-info", "consume a real non-mandatory metadata extension"))),
            Map.entry("IIP-MD05.d", List.of(
                    accept("entity-attributes-direct", "consume a direct Attribute in EntityAttributes under a group root"),
                    accept("entity-attributes-assertion", "consume a signed Assertion in EntityAttributes"),
                    accept("entity-attributes-assertion-conditions", "consume a signed Assertion carrying Conditions"),
                    accept("entity-attributes-multiple", "consume multiple direct Attributes in EntityAttributes"))),
            Map.entry("IIP-MD05.ff", List.of(
                    accept("disco-hints-ipv6-cidr", "consume a DiscoHints IPHint that is an IPv6 CIDR"),
                    accept("disco-hints-ipv4-cidr", "consume a DiscoHints IPHint that is an IPv4 CIDR"))),
            Map.entry("IIP-MD05.cd", List.of(
                    accept("keyvalue-only", "identify the signing key from ds:KeyValue without KeyName"),
                    accept("entity-root", "identify the signing key from ds:X509Certificate without subject hints"))),
            Map.entry("IIP-MD06.a1", List.of(
                    accept("entity-root", "resolve the tested entity from an EntityDescriptor root"),
                    accept("entities-root-one", "resolve it from an EntitiesDescriptor root"),
                    accept("nested-entities", "resolve it through nested EntitiesDescriptor elements"))),
            Map.entry("IIP-MD05.ad", List.of(
                    accept("multiple-signing-keys-first", "sign with the first of two signing keys"),
                    accept("multiple-signing-keys", "sign with the second of two signing keys"),
                    accept("multiple-omitted-keys-first", "sign with the first key with use omitted"),
                    accept("multiple-omitted-keys-second", "sign with the second key with use omitted"))),
            Map.entry("IIP-MD06.a5", List.of(
                    accept("certificate-expired", "use the same public key with different runtime certificate validity and serial"),
                    accept("certificate-unknown-ca", "use the same public key with a different runtime certificate issuer"),
                    accept("certificate-no-digital-signature", "use the same public key with different runtime certificate usage"),
                    accept("keyvalue-only", "match the runtime key to the metadata KeyValue"))),
            Map.entry("IIP-MD06.a7", List.of(
                    accept("keyvalue-only", "consume ds:KeyValue independently"),
                    accept("entity-root", "consume ds:X509Certificate independently"))),
            Map.entry("IIP-MD06.a9", List.of(
                    accept("certificate-expired", "ignore expiration after metadata acceptance"),
                    accept("certificate-not-yet-valid", "ignore notBefore after metadata acceptance"),
                    accept("certificate-empty-subject", "consume an arbitrary certificate subject"),
                    accept("certificate-unknown-ca", "consume an arbitrary certificate issuer"),
                    accept("certificate-critical-extension", "ignore critical certificate extensions"),
                    accept("certificate-noncritical-extension", "ignore non-critical certificate extensions"),
                    accept("certificate-no-digital-signature", "ignore certificate KeyUsage"),
                    accept("certificate-unrelated-eku", "ignore certificate ExtendedKeyUsage"))),
            Map.entry("IIP-MD07.a", List.of(
                    accept("entity-root", "use a single signing key"),
                    accept("multiple-signing-keys-first", "use the first of two signing keys"),
                    accept("multiple-signing-keys", "use the second of two signing keys"),
                    accept("three-signing-keys-first", "use the first of three signing keys"),
                    accept("three-signing-keys-second", "use the second of three signing keys"),
                    accept("three-signing-keys", "use the third of three signing keys"))),
            Map.entry("IIP-MD12.a", List.of(
                    accept("entity-root", "consume one self-signed end-entity certificate"),
                    accept("three-signing-keys", "consume three long-lived self-signed end-entity certificates"),
                    accept("certificate-long-validity", "consume a self-signed certificate with twenty-year validity"))),
            Map.entry("IIP-MD12.b", List.of(
                    accept("certificate-expired", "consume an expired certificate as a key container"),
                    accept("certificate-not-yet-valid", "consume a not-yet-valid certificate as a key container"))),
            Map.entry("IIP-MD12.c", List.of(
                    accept("certificate-sha1", "consume a certificate signed with SHA-1"),
                    accept("certificate-sha512", "consume a certificate signed with SHA-512"))),
            Map.entry("IIP-MD12.d", List.of(
                    accept("certificate-not-yet-valid", "ignore certificate notBefore"),
                    accept("certificate-critical-extension", "ignore a critical extension"),
                    accept("certificate-noncritical-extension", "ignore a non-critical extension"),
                    accept("certificate-no-digital-signature", "ignore KeyUsage when consuming the key"),
                    accept("certificate-unrelated-eku", "ignore unrelated extendedKeyUsage"),
                    accept("certificate-empty-subject", "consume a certificate with an empty subject"),
                    accept("certificate-unknown-ca", "consume a certificate issued by an unknown CA"),
                    accept("entity-root", "consume a valid control certificate"))));

    private MetadataConfigCaseFactory() {}

    static Optional<com.samlscope.core.caseexec.TestCase> create(CaseDefinition definition) {
        if (definition.role() != com.samlscope.core.plan.TargetRole.IDP
                && java.util.Set.of("IIP-MD05.ad", "IIP-MD06.a5", "IIP-MD06.a7",
                        "IIP-MD06.a9", "IIP-MD07.a").contains(definition.obligation())) {
            return Optional.empty();
        }
        var fixtures = FIXTURES.get(definition.obligation());
        return fixtures == null ? Optional.empty() : Optional.of(new MetadataFixtureObservationTestCase(
                definition.id(), definition.role(), fixtures, definition.configurationFailureSemantics()));
    }

    private static Fixture accept(String variant, String purpose) {
        return new Fixture(variant, Behavior.ACCEPT, purpose);
    }

    private static Fixture reject(String variant, String purpose) {
        return new Fixture(variant, Behavior.REJECT, purpose);
    }
}
