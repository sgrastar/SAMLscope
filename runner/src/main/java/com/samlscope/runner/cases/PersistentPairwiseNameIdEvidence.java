package com.samlscope.runner.cases;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Native two-SP proof for SSO05.a3; a second browser success alone is insufficient. */
final class PersistentPairwiseNameIdEvidence {
    static final String CASE = "IIP-SSO05-a3-idp-01";
    static final String SCHEMA = "samlscope-shibboleth-persistent-pairwise-v1";
    static final String FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    static final String AUDIT_FORMAT = "SAMLscope-persistent-v1|%I|%SP|%u|%S|%b|%P";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String RUN = "run_[0-9A-HJKMNP-TV-Z]{26}";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;

    PersistentPairwiseNameIdEvidence(Path directory, TranscriptContentReader content,
            Function<String, byte[]> metadata, SamlDecryptionKeyProvider keys) {
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata);
        this.keys = Objects.requireNonNull(keys);
    }

    Optional<CaseOutcome> evaluate(CaseContext context) {
        var evidence = new LinkedHashSet<EvidenceRef>();
        try {
            require(context.transcriptComplete() && context.runId().matches(RUN));
            var folder = directory.resolve(context.runId()).normalize();
            require(folder.getParent().equals(directory)
                    && Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS));
            var manifest = new JsonCodec().mapper().readTree(original(folder, "manifest.json"));
            require(SCHEMA.equals(text(manifest, "schema")) && context.runId().equals(text(manifest, "runId")));
            var targetRaw = metadata.apply(context.runId());
            require(hash(targetRaw).equals(text(manifest, "targetMetadataSha256")));
            var target = SecureXml.parse(targetRaw).getDocumentElement();
            require(MD.equals(target.getNamespaceURI()) && "EntityDescriptor".equals(target.getLocalName()));
            var targetEntity = target.getAttribute("entityID");
            var trusted = MetadataAlgorithmEvidence.signingKeys(target);
            require(!targetEntity.isBlank() && !trusted.isEmpty());
            var peers = manifest.path("peers");
            require(peers.isArray() && peers.size() == 2);
            var observations = new ArrayList<Peer>();
            for (var peer : peers) {
                var run = text(peer, "runId");
                require(run.matches(RUN) && Arrays.equals(targetRaw, metadata.apply(run)));
                var entity = text(peer, "entityId");
                var spRaw = checked(folder, peer, "nativeMetadataFile", "nativeMetadataSha256");
                var sp = SecureXml.parse(spRaw).getDocumentElement();
                require(MD.equals(sp.getNamespaceURI()) && "EntityDescriptor".equals(sp.getLocalName())
                        && entity.equals(sp.getAttribute("entityID")));
                var roles = children(sp, MD, "SPSSODescriptor");
                require(roles.size() == 1 && Arrays.asList(roles.getFirst().getAttribute(
                        "protocolSupportEnumeration").split("\\s+")).contains(P));
                var requestKeys = certificates(roles.getFirst(), "signing");
                require(!requestKeys.isEmpty());
                var entries = new HashMap<String, TranscriptEntry>();
                for (var entry : context.transcript().list(run)) {
                    require(run.equals(entry.runId()) && entries.put(entry.id(), entry) == null);
                }
                var exchanges = peer.path("exchanges");
                require(exchanges.isArray() && exchanges.size() > 0);
                var audit = new String(checked(folder, peer, "auditFile", "auditSha256"), StandardCharsets.UTF_8);
                var identifiers = new ArrayList<Element>();
                String principal = null;
                Instant first = null, last = null;
                var requestIds = new HashSet<String>();
                for (var exchange : exchanges) {
                    var request = entry(entries, text(exchange, "requestReference"), Direction.OUTBOUND);
                    var response = entry(entries, text(exchange, "responseReference"), Direction.INBOUND);
                    require(!request.timestamp().isAfter(response.timestamp()));
                    var requestXml = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
                    var responseXml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
                    require(P.equals(requestXml.getNamespaceURI()) && "AuthnRequest".equals(requestXml.getLocalName()));
                    var id = requestXml.getAttribute("ID");
                    require(!id.isBlank() && requestIds.add(id));
                    var verifier = new com.samlscope.saml.crypto.XmlSignatureVerifier();
                    require(verifier.hasValidEnvelopedReferenceDigests(requestXml)
                            && requestKeys.stream().anyMatch(certificate -> verifier.hasValidEnvelopedSignature(requestXml, certificate)));
                    var issuers = children(requestXml, S, "Issuer");
                    var policies = children(requestXml, P, "NameIDPolicy");
                    require(issuers.size() == 1 && entity.equals(issuers.getFirst().getTextContent())
                            && policies.size() == 1 && FORMAT.equals(policies.getFirst().getAttribute("Format")));
                    var recipient = requestXml.getAttribute("AssertionConsumerServiceURL");
                    require(!recipient.isBlank() && children(roles.getFirst(), MD, "AssertionConsumerService").stream()
                            .anyMatch(acs -> recipient.equals(acs.getAttribute("Location"))));
                    Optional<PlanCredentials> credentials = Optional.empty();
                    if (!children(responseXml, S, "EncryptedAssertion").isEmpty()) {
                        var privateKey = keys.keyFor(run).orElseThrow();
                        var encryptionCertificates = new ArrayList<X509Certificate>();
                        for (var descriptor : children(roles.getFirst(), MD, "KeyDescriptor")) {
                            if (!List.of("", "encryption").contains(descriptor.getAttribute("use"))) continue;
                            var certificates = descriptor.getElementsByTagNameNS(DS, "X509Certificate");
                            for (int i = 0; i < certificates.getLength(); i++) {
                                var der = Base64.getMimeDecoder().decode(certificates.item(i).getTextContent());
                                encryptionCertificates.add((X509Certificate)CertificateFactory.getInstance("X.509")
                                        .generateCertificate(new java.io.ByteArrayInputStream(der)));
                            }
                        }
                        require(encryptionCertificates.size() == 1);
                        credentials = Optional.of(new PlanCredentials(privateKey, encryptionCertificates.getFirst()));
                    }
                    var assertion = VerifiedResponseAssertion.read(responseXml, targetEntity, trusted,
                            sp, credentials, id, recipient);
                    var subjects = children(assertion, S, "Subject");
                    require(subjects.size() == 1);
                    var names = children(subjects.getFirst(), S, "NameID");
                    require(names.size() == 1 && FORMAT.equals(names.getFirst().getAttribute("Format"))
                            && !names.getFirst().getTextContent().isBlank());
                    var user = principal(audit, id, entity);
                    require(principal == null || principal.equals(user));
                    principal = user;
                    identifiers.add(names.getFirst());
                    first = first == null || request.timestamp().isBefore(first) ? request.timestamp() : first;
                    last = last == null || response.timestamp().isAfter(last) ? response.timestamp() : last;
                    evidence.add(new EvidenceRef("transcript", request.id()));
                    evidence.add(new EvidenceRef("transcript", response.id()));
                }
                observations.add(new Peer(run, entity, principal, identifiers, first, last));
            }
            require(observations.stream().filter(p -> context.runId().equals(p.run())).count() == 1);
            require(context.runId().equals(observations.get(0).run())
                    && !observations.get(0).run().equals(observations.get(1).run())
                    && !observations.get(0).entity().equals(observations.get(1).entity())
                    && observations.get(0).principal().equals(observations.get(1).principal()));
            configuration(folder, manifest, observations);
            // Affiliation and previously assigned alternate identifiers require additional native
            // history evidence before a mismatch can be called a product violation. This narrow
            // adapter adopts only the directly proven two-SP success; uncertain mismatches remain
            // NOT_VERIFIED through the scenario's existing result.
            for (var peer : observations) for (var name : peer.names()) {
                require(!name.hasAttribute("NameQualifier") || targetEntity.equals(name.getAttribute("NameQualifier")));
                require(!name.hasAttribute("SPNameQualifier") || peer.entity().equals(name.getAttribute("SPNameQualifier")));
                require(!name.hasAttribute("SPProvidedID"));
            }
            for (var left : observations.get(0).names()) for (var right : observations.get(1).names())
                require(!left.getTextContent().equals(right.getTextContent()));
            var details = Map.<String,Object>of("peer_count", observations.size(), "same_principal_proven", true,
                    "secondary_run", observations.stream().filter(p -> !context.runId().equals(p.run())).findFirst().orElseThrow().run(),
                    "adapter", "shibboleth-native-persistent-pairwise");
            return Optional.of(new CaseOutcome(Outcome.SATISFIED, null,
                    "idp.persistent-pairwise.observed", "case.idp.persistent-pairwise.observed",
                    List.copyOf(evidence), details));
        } catch (Exception unproven) {
            return Optional.empty();
        }
    }

    private void configuration(Path folder, JsonNode manifest, List<Peer> peers) throws Exception {
        var files = manifest.path("configurationFiles");
        require(files.isArray() && files.size() == 5);
        var kinds = new HashSet<String>();
        for (var file : files) {
            var kind = text(file, "kind");
            require(kinds.add(kind));
            var before = checked(folder, file, "originalFile", "originalSha256");
            var configured = checked(folder, file, "configuredFile", "configuredSha256");
            require(Arrays.equals(before, checked(folder, file, "finalFile", "finalSha256")));
            var readBacks = file.path("readBacks");
            require(readBacks.isArray() && readBacks.size() == 4);
            var phases = new HashSet<String>();
            for (var readBack : readBacks) {
                var phase = text(readBack, "phase");
                require(phases.add(phase) && Arrays.equals(configured,
                        checked(folder, readBack, "file", "sha256")));
                var peer = peers.get(phase.startsWith("primary-") ? 0 : 1);
                var recorded = Instant.parse(text(readBack, "recordedAt"));
                if (phase.endsWith("-before")) require(!recorded.isAfter(peer.first()));
                else require(phase.endsWith("-after") && !recorded.isBefore(peer.last()));
            }
            require(phases.equals(Set.of("primary-before", "primary-after", "secondary-before", "secondary-after")));
            switch (kind) {
                case "nameid-properties" -> {
                    var properties = new Properties();
                    properties.load(new java.io.ByteArrayInputStream(configured));
                    require("uid".equals(properties.getProperty("idp.persistentId.sourceAttribute"))
                            && !properties.getProperty("idp.persistentId.salt", "").isBlank());
                }
                case "nameid-xml" -> {
                    var xml = SecureXml.parse(configured);
                    var lists = xml.getElementsByTagNameNS("http://www.springframework.org/schema/util", "list");
                    boolean enabled = false;
                    for (int i=0; i<lists.getLength(); i++) {
                        var list = (Element)lists.item(i);
                        if (!"shibboleth.SAML2NameIDGenerators".equals(list.getAttribute("id"))) continue;
                        for (var ref : children(list, "http://www.springframework.org/schema/beans", "ref"))
                            enabled |= "shibboleth.SAML2PersistentGenerator".equals(ref.getAttribute("bean"));
                    }
                    require(enabled);
                }
                case "attribute-resolver-xml" -> {
                    var xml = SecureXml.parse(configured);
                    var definitions = xml.getElementsByTagNameNS("urn:mace:shibboleth:2.0:resolver", "AttributeDefinition");
                    boolean principal = false;
                    for (int i=0; i<definitions.getLength(); i++) {
                        var definition = (Element)definitions.item(i);
                        var type = definition.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "type");
                        int colon = type.indexOf(':');
                        var local = colon < 0 ? type : type.substring(colon + 1);
                        var prefix = colon < 0 ? null : type.substring(0, colon);
                        principal |= "uid".equals(definition.getAttribute("id")) && "PrincipalName".equals(local)
                                && "urn:mace:shibboleth:2.0:resolver".equals(definition.lookupNamespaceURI(prefix));
                    }
                    require(principal);
                }
                case "audit-xml" -> {
                    var elements = SecureXml.parse(configured).getElementsByTagName("*");
                    boolean configuredFormat = false;
                    for (int i=0; i<elements.getLength(); i++)
                        configuredFormat |= AUDIT_FORMAT.equals(((Element)elements.item(i)).getAttribute("value"));
                    require(configuredFormat);
                }
                case "metadata-provider-xml" -> {
                    var providers = SecureXml.parse(configured).getElementsByTagNameNS(
                            "urn:mace:shibboleth:2.0:metadata", "MetadataProvider");
                    boolean nativeProvider = false;
                    for (int i=0; i<providers.getLength(); i++)
                        nativeProvider |= "DynamicHTTPMetadataProvider".equals(((Element)providers.item(i))
                                .getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "type"));
                    require(nativeProvider);
                }
                default -> throw new IllegalArgumentException("Unknown native configuration kind");
            }
        }
        require(kinds.equals(Set.of("nameid-xml", "nameid-properties", "audit-xml",
                "metadata-provider-xml", "attribute-resolver-xml")));
    }

    private String principal(String audit, String request, String entity) {
        var users = new HashSet<String>();
        for (var line : audit.lines().toList()) {
            int start = line.indexOf("SAMLscope-persistent-v1|");
            if (start < 0) continue;
            var fields = line.substring(start).strip().split("\\|", -1);
            if (fields.length != 7 || !request.equals(fields[1])) continue;
            require(entity.equals(fields[2]) && !fields[3].isBlank() && "Success".equals(fields[4])
                    && "POST".equals(fields[5])
                    && "http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(fields[6]));
            users.add(fields[3]);
        }
        require(users.size() == 1);
        return users.iterator().next();
    }

    private TranscriptEntry entry(Map<String,TranscriptEntry> entries, String id, Direction direction) {
        var entry = entries.get(id);
        require(entry != null && entry.direction() == direction && entry.decodedSamlRef() != null);
        return entry;
    }
    private byte[] checked(Path folder, JsonNode object, String file, String sha) throws Exception {
        var raw = original(folder, text(object, file));
        require(hash(raw).equals(text(object, sha)));
        return raw;
    }
    private byte[] original(Path folder, String name) throws Exception {
        var path = folder.resolve(name).normalize();
        require(path.getParent().equals(folder) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && Files.size(path) <= 2_097_152);
        return Files.readAllBytes(path);
    }
    private String text(JsonNode node, String key) {
        require(node.path(key).isTextual() && !node.path(key).asText().isBlank());
        return node.path(key).asText();
    }
    private String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private static List<Element> children(Element root, String ns, String name) {
        return MetadataAlgorithmEvidence.children(root, ns, name);
    }
    private static List<X509Certificate> certificates(Element role, String purpose) throws Exception {
        var result = new ArrayList<X509Certificate>();
        for (var descriptor : children(role, MD, "KeyDescriptor")) {
            if (!List.of("", purpose).contains(descriptor.getAttribute("use"))) continue;
            for (var info : children(descriptor, DS, "KeyInfo"))
                for (var data : children(info, DS, "X509Data"))
                    for (var certificate : children(data, DS, "X509Certificate")) {
                        var der = Base64.getMimeDecoder().decode(certificate.getTextContent());
                        result.add((X509Certificate)CertificateFactory.getInstance("X.509")
                                .generateCertificate(new java.io.ByteArrayInputStream(der)));
                    }
        }
        return result;
    }
    private static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("Persistent pairwise proof unavailable");
    }
    private record Peer(String run, String entity, String principal, List<Element> names, Instant first, Instant last) {}
}
