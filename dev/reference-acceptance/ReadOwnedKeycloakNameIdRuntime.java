package com.samlscope.api;

import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;

import com.samlscope.core.casedef.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import org.w3c.dom.Element;

/** Read-only public originals from one explicitly owned native Keycloak NameID Run.
 * Native protocol qualification preserves the Suite outcome and never replaces approved controls. */
public final class ReadOwnedKeycloakNameIdRuntime {
    static final String SELECTED = "IIP-IDP10-d-idp-01";
    static final String CASE_DIGEST = "sha256:a02075559dff2bf93b50bcc17a601f9037093d5405a9ee93ff5f7f0e80fa346a";
    static final String VERSION = "functional-case-v2-nameid";
    static final String PROFILE_DIGEST = "sha256:05558838bf997f81d5be63d423df254b547ffe7c0600683157b6dadd566b7448";
    static final String TARGET = "http://localhost:28080/realms/samlscope";
    static final String SSO = TARGET + "/protocol/saml";
    static final String TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    static final String PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    static final Set<String> ERRORS = Set.of("urn:oasis:names:tc:SAML:2.0:status:Requester", "urn:oasis:names:tc:SAML:2.0:status:Responder");
    static final List<String> FIXTURES = List.of("format-transient", "format-persistent", "sp-name-qualifier");
    static final Set<String> VARIANTS = Set.of("IIP-IDP10.d#v-534e8baf05", "IIP-IDP10.d#v-898a349947",
            "IIP-IDP10.d#v-96ea6f9410", "IIP-IDP10.d#v-e2c03ed209", "IIP-IDP10.d#v-e4467623ff");
    static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    static final Pattern REDACTED_COOKIE = Pattern.compile("([!#$%&'*+.^_`|~0-9A-Za-z-]+)=<redacted: ([0-9]{1,7}) bytes>");

    public static void main(String[] args) throws Exception {
        require(args.length == 5 && args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Set.of("scope", "runtime").contains(args[2]) && args[4].matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}"),
                "Usage: <data root> <bound Run> scope|runtime <Suite public metadata> <owned generation>");
        Path data = Path.of(args[0]).toAbsolutePath();
        require(data.equals(data.normalize()), "Noncanonical data root"); rejectSymlinkAncestors(data);
        var codec = new JsonCodec(); var result = new LinkedHashMap<String,Object>();
        try (var db = readOnlyDatabase(data.resolve("samlscope.db"))) {
            var run = codec.read(boundDocument(db, "runs", args[1]), TestRun.class);
            var plan = codec.read(boundDocument(db, "plans", run.planId()), TestPlan.class);
            requireBoundScope(run, plan, args[1], args[4]);
            var documents = CatalogDocuments.load(); var releases = FunctionalProfileDocuments.load();
            var resolver = new PinnedFunctionalCaseDefinitionResolver(releases.artifacts(), releases.digests(),
                    Map.of("tests/coverage.yaml", documents.bytes("tests/coverage.yaml"),
                            "tests/cases.yaml", documents.bytes("tests/cases.yaml"),
                            "tests/predicates.yaml", documents.bytes("tests/predicates.yaml")),
                    CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml")),
                    CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml")));
            requireIdentity(resolver.identity(FunctionalProfile.BROWSER_SSO_IDP));
            var membership = resolver.resolve(plan.definitionIdentity()).cases();
            var selected = only(membership.stream().filter(c -> SELECTED.equals(c.id())).toList(), "actual approved NameID membership");
            requireApprovedCase(selected);
            result.put("schema", "owned-keycloak-nameid-native-v1"); result.put("mode", args[2]);
            result.put("runId", run.id()); result.put("planId", plan.id()); result.put("generation", args[4]);
            result.put("caseId", SELECTED); result.put("caseDigest", selected.caseDigest());
            result.put("definitionIdentity", plan.definitionIdentity()); result.put("targetEntityId", TARGET);
            result.put("databaseAccess", "URI-escaped-mode-ro-query-only");
            result.put("approvedControlReplayRequiredForAdoption", true); result.put("wholeRunConformance", "NOT_QUALIFIED");
            result.put("canonicalAdoption", false); result.put("protocolSubmissionsByReader", 0); result.put("privateKeyReads", 0);
            if (args[2].equals("scope")) {
                int executions = count(db, "case_executions", run.id()), actions = count(db, "outbox_actions", run.id()), entries = count(db, "transcript_entries", run.id());
                require(Set.of(RunStatus.CREATED, RunStatus.RUNNING).contains(run.status())
                        && !run.context().containsKey("authnRequestId") && executions == 0 && actions == 0 && entries == 0,
                        "Cold scope contains authentication, execution, action, or transcript evidence");
                result.put("qualificationOutcome", "SCOPE_VERIFIED"); result.put("selectedCaseOutcome", "NOT_STARTED");
                result.put("actualCaseExecutions", executions); result.put("actualOutboxActions", actions); result.put("transcriptEntries", entries);
                result.put("selectedCaseEvidence", List.of()); result.put("selectedActionPairs", List.of());
                result.put("portableEvidenceReferences", List.of()); result.put("transcriptOriginals", List.of());
            } else {
                var execution = selectedExecution(db, codec, run.id());
                result.put("selectedCaseOutcome", execution.outcome().outcome().name());
                result.put("selectedCaseReasonCode", execution.outcome().reasonCode());
                result.put("selectedCaseEvidence", execution.outcome().evidence().stream().map(EvidenceRef::reference).toList());
                result.put("qualificationOutcome", "NOT_VERIFIED");
                try { qualifyRuntime(db, codec, data, run, plan, Path.of(args[3]), execution, result); }
                catch (IllegalArgumentException uncertain) { result.put("diagnostics", List.of(safeMessage(uncertain))); }
            }
        }
        System.out.println(codec.write(result));
    }

    static void requireIdentity(FunctionalDefinitionIdentity identity) {
        require(identity != null && identity.profile() == FunctionalProfile.BROWSER_SSO_IDP
                && VERSION.equals(identity.version()) && PROFILE_DIGEST.equals(identity.digest()), "Actual V2 NameID profile identity differs");
    }

    static void requireBoundScope(TestRun run, TestPlan plan, String runId, String generation) {
        require(run != null && plan != null && runId.equals(run.id()) && run.planId().equals(plan.id())
                && plan.id().matches("plan_[0-9A-HJKMNP-TV-Z]{26}") && plan.profile() == FunctionalProfile.BROWSER_SSO_IDP
                && plan.target().kind() == TargetKind.IDP && TARGET.equals(plan.target().entityId())
                && plan.name().equals("Owned Keycloak public-CI NameID v2 " + generation)
                && plan.parameters().requestSigningMode() == TestPlan.RequestSigningMode.REQUIRED,
                "Foreign Run, Plan, target, generation, or signing configuration");
        requireIdentity(plan.definitionIdentity());
    }

    static void requireApprovedCase(CaseDefinitionCatalog.CaseDefinition selected) {
        require(SELECTED.equals(selected.id()) && "IIP-IDP10.d".equals(selected.obligation())
                && CASE_DIGEST.equals(selected.caseDigest()) && selected.role() == TargetRole.IDP
                && selected.mode() == CaseDefinitionCatalog.ExecutionMode.BROWSER && selected.milestone() == CaseDefinitionCatalog.Milestone.M1
                && selected.coversVariants().size() == VARIANTS.size() && Set.copyOf(selected.coversVariants()).equals(VARIANTS)
                && selected.variantScopes().values().stream().allMatch(v -> v == CaseDefinitionCatalog.VariantScope.OWNER_CONDITION)
                && selected.controls().size() == 2, "Approved NameID case boundary differs");
        require(selected.controls().stream().anyMatch(c -> c.id().equals("iip-idp10-d-idp-01-positive")
                        && c.kind() == CaseDefinitionCatalog.ControlKind.POSITIVE && c.fixture().equals("idp-core-no-ecp"))
                && selected.controls().stream().anyMatch(c -> c.id().equals("iip-idp10-d-idp-01-negative")
                        && c.kind() == CaseDefinitionCatalog.ControlKind.NEGATIVE && c.fixture().equals("mut-iip-idp10-d-idp")),
                "Approved baseline or mutant boundary differs");
    }

    static void qualifyRuntime(Connection db, JsonCodec codec, Path data, TestRun run, TestPlan plan,
            Path suiteMetadataPath, CaseExecution stored, Map<String,Object> result) throws Exception {
        var entries = nativeEntries(db, codec, run.id()); var actions = selectedOutbox(db, codec, run.id());
        require(actions.size() == 3, "Selected scenario requires exactly three sent actions");
        require(run.context().get("authnRequestId") instanceof String
                && entries.stream().filter(e -> e.direction() == Direction.OUTBOUND && SELECTED.equals(e.samlSummary().get("scenario_case_id"))).count() == 3,
                "Normal authentication identity or exact selected request count unavailable");
        var normalRequest = only(entries.stream().filter(e -> e.direction() == Direction.OUTBOUND
                && "AuthnRequest".equals(e.samlSummary().get("type"))
                && Objects.equals(e.correlationId(), run.context().get("authnRequestId"))
                && !e.samlSummary().containsKey("scenario_case_id")).toList(), "normal M0 request");
        var normalResponse = only(entries.stream().filter(e -> e.direction() == Direction.INBOUND
                && "Response".equals(e.samlSummary().get("type")) && Objects.equals(e.correlationId(), run.context().get("authnRequestId"))).toList(), "normal accepted M0 response");
        require(Boolean.TRUE.equals(normalResponse.samlSummary().get("normalFlowAccepted"))
                && entries.stream().filter(e -> Boolean.TRUE.equals(e.samlSummary().get("normalFlowAccepted"))).count() == 1
                && !normalResponse.timestamp().isBefore(normalRequest.timestamp()), "Normal accepted arrival is absent, duplicated, or precedes request");
        var scoped = new ArrayList<TranscriptEntry>(); scoped.add(normalRequest); scoped.add(normalResponse);
        var pairs = new ArrayList<Map<String,Object>>(); Instant previous = normalResponse.timestamp();
        for (String fixture : FIXTURES) {
            var request = only(entries.stream().filter(e -> e.direction() == Direction.OUTBOUND
                    && "AuthnRequest".equals(e.samlSummary().get("type")) && SELECTED.equals(e.samlSummary().get("scenario_case_id"))
                    && fixture.equals(e.samlSummary().get("fixture_id"))).toList(), "selected fixture request");
            require(request.samlSummary().get("action_id") instanceof String, "Selected request action identity unavailable");
            String actionId = (String) request.samlSummary().get("action_id");
            var action = only(actions.stream().filter(a -> a.action().actionId().equals(actionId)).toList(), "exact selected outbox action");
            var response = only(entries.stream().filter(e -> e.direction() == Direction.INBOUND
                    && "Response".equals(e.samlSummary().get("type")) && ("_" + actionId).equals(e.correlationId())).toList(), "selected correlated native response");
            require(action.status() == OutboxStatus.SENT && action.action().kind() == OutboundKind.AUTHN_REQUEST
                    && !action.action().requiresEphemeralCredential() && actionId.equals(request.correlationId())
                    && confirmedBrowserDelivery(action, request.id(), response.id()) && action.action().target().toASCIIString().equals(request.url())
                    && Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted"))
                    && !request.timestamp().isBefore(previous) && !response.timestamp().isBefore(request.timestamp()),
                    "Selected action, request, response, or ordered fixture scope differs");
            previous = response.timestamp(); scoped.add(request); scoped.add(response);
            var pair = new LinkedHashMap<String,Object>(); pair.put("fixtureId", fixture); pair.put("actionId", actionId);
            pair.put("requestReference", request.id()); pair.put("responseReference", response.id()); pairs.add(pair);
        }
        require(scoped.size() == 8 && scoped.stream().map(TranscriptEntry::id).distinct().count() == 8, "Exactly eight unique originals required");
        requireEvidence(stored.outcome().evidence(), pairs.stream().map(p -> (String) p.get("responseReference")).toList());
        var originals = new LinkedHashMap<String,Original>(); long total = 0;
        for (var entry : scoped) {
            var value = readOriginal(data, entry); total += (long) value.body().length + value.decoded().length;
            require(total <= MAX_EXPORTED, "Selected original bytes exceed export bound"); originals.put(entry.id(), value);
        }
        byte[] suiteMetadata = publicFile(suiteMetadataPath), targetMetadata = publicFile(data.resolve("target-metadata").resolve(run.id() + ".xml"));
        var normal = saml(originals, normalRequest); String issuer = single(normal, A, "Issuer").getTextContent();
        var suiteEntity = suiteEntity(suiteMetadata, plan.id(), issuer); var suiteCerts = certificates(suiteEntity);
        String acs = issuer + "/sp/acs/0"; require(registeredAcsZero(suiteEntity, acs), "Actual registered ACS 0 unavailable");
        var target = new TargetMetadataParser().parse(targetMetadata, TARGET); var targetCerts = target.signingCertificates();
        require(!targetCerts.isEmpty() && target.singleSignOnServices().stream().anyMatch(e -> e.location().toASCIIString().equals(SSO) && POST.equals(e.binding()))
                && target.singleSignOnServices().stream().anyMatch(e -> e.location().toASCIIString().equals(SSO)
                        && "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".equals(e.binding())), "Native metadata endpoint or signing certificate unavailable");
        require(normal.getAttribute("ID").equals(run.context().get("authnRequestId"))
                && normal.getAttribute("AssertionConsumerServiceURL").equals(acs) && normal.getAttribute("Destination").equals(SSO)
                && endpoint(normalRequest.url()).equals(SSO) && normalRequest.correlationId().equals(normal.getAttribute("ID")), "Normal M0 request binding differs");
        verifyRequest(originals, normalRequest, suiteCerts, true);
        var normalProof = verifyResponse(originals, normalResponse, normal, TARGET, targetCerts, issuer, acs, null);
        require(normalProof.success(), "Normal M0 did not establish a native Success");
        var proofs = new ArrayList<Map<String,Object>>();
        var policyProofs = new ArrayList<ResponseProof>();
        for (var pair : pairs) {
            var request = only(scoped.stream().filter(e -> e.id().equals(pair.get("requestReference"))).toList(), "paired request");
            var response = only(scoped.stream().filter(e -> e.id().equals(pair.get("responseReference"))).toList(), "paired response");
            var authn = saml(originals, request); String fixture = (String) pair.get("fixtureId"), actionId = (String) pair.get("actionId");
            require(authn.getAttribute("ID").equals("_" + actionId) && issuer.equals(single(authn, A, "Issuer").getTextContent())
                    && authn.getAttribute("Destination").equals(SSO) && request.url().equals(SSO)
                    && authn.getAttribute("AssertionConsumerServiceURL").equals(acs), "Selected request correlation, issuer, endpoint, or ACS differs");
            requirePolicy(authn, fixture, issuer); verifyRequest(originals, request, suiteCerts, false);
            var action = only(actions.stream().filter(a -> a.action().actionId().equals(actionId)).toList(), "paired action");
            require(Arrays.equals(action.action().payload(), original(originals, request).decoded()), "Selected outbox payload differs from original request");
            var proof = verifyResponse(originals, response, authn, TARGET, targetCerts, issuer, acs, fixture);
            policyProofs.add(proof); var export = new LinkedHashMap<String,Object>(proof.export()); export.put("fixtureId", fixture); proofs.add(export);
        }
        requireOutcomeExplained(stored.outcome().outcome(), policyProofs);
        result.put("qualificationOutcome", "VERIFIED"); result.put("selectedCaseEvidence", pairs.stream().map(p -> p.get("responseReference")).toList());
        result.put("normalRequestReference", normalRequest.id()); result.put("normalResponseReference", normalResponse.id());
        result.put("selectedActionPairs", pairs); result.put("portableEvidenceReferences", scoped.stream().map(TranscriptEntry::id).toList());
        result.put("transcriptOriginals", originals.values().stream().map(Original::export).toList());
        result.put("selectedRegisteredScenarioProven", true); result.put("nativeRequiredRequestShapesProven", true);
        result.put("nativeResponseProofs", proofs); result.put("suitePublicMetadataSha256", hash(suiteMetadata)); result.put("runMetadataSnapshotSha256", hash(targetMetadata));
        result.put("ownedRedactedCookieMetadataOmitted", true); result.put("storedRowsUnchanged", true);
        result.put("originalExportScope", "only-normal-and-selected-case");
    }

    /** Actual dispatcher completion binds SENT to the accepted inbound response, not its earlier handoff. */
    static boolean confirmedBrowserDelivery(OutboxEntry action, String requestReference, String responseReference) {
        return requestReference != null && responseReference != null && !requestReference.equals(responseReference)
                && action.status() == OutboxStatus.SENT && responseReference.equals(action.transcriptEntryId())
                && "inbound-response".equals(action.sendResult().get("confirmed_by"));
    }

    static void requireEvidence(List<EvidenceRef> stored, List<String> responses) {
        require(responses.size() == 3 && new HashSet<>(responses).size() == 3 && stored.size() == 3
                && stored.stream().allMatch(e -> "transcript".equals(e.kind()))
                && stored.stream().map(EvidenceRef::reference).collect(java.util.stream.Collectors.toSet()).equals(Set.copyOf(responses)),
                "Stored selected outcome evidence differs from the three distinct response originals");
    }

    static boolean registeredAcsZero(Element entity, String acs) {
        return children(single(entity, MD, "SPSSODescriptor"), MD, "AssertionConsumerService").stream()
                .filter(e -> acs.equals(e.getAttribute("Location")) && POST.equals(e.getAttribute("Binding")) && "0".equals(e.getAttribute("index"))).count() == 1;
    }

    static String endpoint(String url) {
        var uri = URI.create(url); require(uri.getUserInfo() == null && uri.getFragment() == null && uri.getHost() != null, "Endpoint credentials or fragment");
        return uri.getScheme() + "://" + uri.getRawAuthority() + uri.getRawPath();
    }

    static void requirePolicy(Element request, String fixture, String issuer) {
        require(FIXTURES.contains(fixture) && POST.equals(request.getAttribute("ProtocolBinding"))
                && !request.hasAttribute("AssertionConsumerServiceIndex"), "Formal request binding or fixture differs");
        var policy = single(request, P, "NameIDPolicy");
        require((fixture.equals("format-persistent") ? PERSISTENT : TRANSIENT).equals(policy.getAttribute("Format")), "Actual policy Format differs");
        if (fixture.equals("sp-name-qualifier")) require(issuer.equals(policy.getAttribute("SPNameQualifier")), "Actual requested SPNameQualifier differs");
        else require(!policy.hasAttribute("SPNameQualifier"), "Unexpected requested SPNameQualifier");
        require(fixture.equals("format-persistent") ? "true".equals(policy.getAttribute("AllowCreate")) : !policy.hasAttribute("AllowCreate"), "Actual AllowCreate shape differs");
    }

    static void verifyRequest(Map<String,Original> originals, TranscriptEntry entry, List<X509Certificate> certificates, boolean normal) {
        var xml = saml(originals, entry); requireProtocol(xml, "AuthnRequest"); requireUniqueIds(xml);
        require(entry.direction() == Direction.OUTBOUND && "AuthnRequest".equals(entry.samlSummary().get("type")), "Request transcript type differs");
        if (normal) {
            require(entry.method().equals("GET") && entry.rawQuery() != null && Objects.equals(URI.create(entry.url()).getRawQuery(), entry.rawQuery())
                    && original(originals, entry).body().length == 0 && certificates.stream().anyMatch(c ->
                            new RedirectSignatureVerifier().isValidForMessage(entry.rawQuery(), c, original(originals, entry).decoded())), "Normal raw Redirect signature unproven");
        } else {
            require(entry.method().equals("POST") && entry.rawQuery() == null, "Formal signed POST request unavailable");
            verifySigned(xml, certificates); requireForm(original(originals, entry).body(), original(originals, entry).decoded(), "SAMLRequest");
        }
    }

    record ResponseProof(boolean success, boolean formatMismatch, boolean explicitSpNameQualifierMismatch, boolean implicitSameSpProven) {
        boolean policyMismatch() { return formatMismatch || explicitSpNameQualifierMismatch; }
        Map<String,Object> export() { return Map.of("responseProof", success ? "native-success" : "native-explicit-error",
                "formatMismatch", formatMismatch, "explicitSpNameQualifierMismatch", explicitSpNameQualifierMismatch,
                "implicitSameSpProven", implicitSameSpProven); }
    }

    static void requireOutcomeExplained(Outcome actualStoredOutcome, List<ResponseProof> proofs) {
        require(proofs.size() == 3 && proofs.stream().allMatch(Objects::nonNull)
                && ((Set.of(Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE).contains(actualStoredOutcome) && proofs.stream().noneMatch(ResponseProof::policyMismatch))
                    || (actualStoredOutcome == Outcome.VIOLATED && proofs.stream().anyMatch(ResponseProof::policyMismatch))),
                "Stored selected outcome is not explained by the authenticated native policy responses");
    }

    static ResponseProof verifyResponse(Map<String,Original> originals, TranscriptEntry entry, Element request,
            String entity, List<X509Certificate> certificates, String issuer, String acs, String fixture) {
        var root = saml(originals, entry); requireProtocol(root, "Response"); requireUniqueIds(root);
        require(entry.direction() == Direction.INBOUND && entry.method().equals("POST") && "Response".equals(entry.samlSummary().get("type"))
                && entry.url().equals(acs) && root.getAttribute("Destination").equals(acs)
                && root.getAttribute("InResponseTo").equals(request.getAttribute("ID")) && entry.correlationId().equals(request.getAttribute("ID"))
                && entity.equals(single(root, A, "Issuer").getTextContent()), "Native response Run/request/entity/ACS binding differs");
        verifySigned(root, certificates); requireForm(original(originals, entry).body(), original(originals, entry).decoded(), "SAMLResponse");
        String value = status(root);
        if (ERRORS.contains(value)) {
            require(children(root, A, "Assertion").isEmpty() && children(root, A, "EncryptedAssertion").isEmpty(), "Error status contains ambiguous assertions");
            return new ResponseProof(false, false, false, false);
        }
        require(SUCCESS.equals(value), "Response status is neither native Success nor explicit Requester/Responder");
        require(children(root, A, "EncryptedAssertion").isEmpty(), "Encrypted assertion has no public plaintext proof");
        var assertion = single(root, A, "Assertion"); require(entity.equals(single(assertion, A, "Issuer").getTextContent()), "Assertion issuer differs");
        verifySigned(assertion, certificates); var subject = single(assertion, A, "Subject");
        require(children(subject, A, "EncryptedID").isEmpty() && children(subject, A, "BaseID").isEmpty(), "Encrypted or ambiguous subject has no plaintext NameID proof");
        var name = single(subject, A, "NameID"); require(!name.getTextContent().isBlank() && name.hasChildNodes()
                && elementChildren(name).isEmpty(), "Actual direct Subject NameID content unavailable");
        boolean formatMismatch = false, qualifierMismatch = false, implicit = false;
        if (fixture != null) {
            require(!name.getAttribute("Format").isBlank(), "Actual returned NameID Format is opaque or absent");
            formatMismatch = !(fixture.equals("format-persistent") ? PERSISTENT : TRANSIENT).equals(name.getAttribute("Format"));
            if (fixture.equals("sp-name-qualifier")) {
                if (name.hasAttribute("SPNameQualifier")) {
                    require(!name.getAttribute("SPNameQualifier").isBlank(), "Returned explicit SPNameQualifier is opaque or empty");
                    qualifierMismatch = !issuer.equals(name.getAttribute("SPNameQualifier"));
                } else { requireImplicitSameSp(root, assertion, name, issuer, acs); implicit = true; }
            }
        }
        return new ResponseProof(true, formatMismatch, qualifierMismatch, implicit);
    }

    static void requireImplicitSameSp(Element response, Element assertion, Element name, String issuer, String acs) {
        require(Set.of(TRANSIENT, PERSISTENT).contains(name.getAttribute("Format"))
                && response.getAttribute("Destination").equals(acs) && !name.hasAttribute("SPNameQualifier")
                && children(single(assertion, A, "Subject"), A, "NameID").size() == 1
                && single(single(assertion, A, "Subject"), A, "NameID") == name,
                "Implicit qualification is outside the own transient/persistent Subject or registered Destination");
        var restrictions = children(single(assertion, A, "Conditions"), A, "AudienceRestriction");
        require(!restrictions.isEmpty(), "Implicit same-SP audience proof absent");
        for (var restriction : restrictions) {
            var audiences = children(restriction, A, "Audience");
            require(!audiences.isEmpty() && audiences.stream().allMatch(e -> elementChildren(e).isEmpty() && issuer.equals(e.getTextContent())),
                    "Own Assertion audiences are not exclusively the Suite issuer");
        }
    }

    static List<Element> elementChildren(Element root) {
        var values = new ArrayList<Element>(); for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) if (node instanceof Element e) values.add(e); return values;
    }

    static void requireProtocol(Element root, String type) {
        require(P.equals(root.getNamespaceURI()) && type.equals(root.getLocalName()) && "2.0".equals(root.getAttribute("Version"))
                && !root.getAttribute("ID").isBlank(), "SAML protocol identity differs");
    }

    static void requireUniqueIds(Element root) {
        var ids = new HashSet<String>(); var nodes = root.getOwnerDocument().getElementsByTagName("*");
        for (int i = 0; i < nodes.getLength(); i++) { var element = (Element) nodes.item(i);
            if (element.hasAttribute("ID")) require(!element.getAttribute("ID").isBlank() && ids.add(element.getAttribute("ID")), "Duplicate or empty XML ID"); }
    }

    static void verifySigned(Element root, List<X509Certificate> certificates) {
        require(children(root, DS, "Signature").size() == 1 && !root.getAttribute("ID").isBlank()
                && certificates != null && !certificates.isEmpty() && certificates.stream().anyMatch(c ->
                        new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(root)
                                && new XmlSignatureVerifier().hasValidEnvelopedSignature(root, c)), "Actual direct XML signature unproven");
    }

    static void requireForm(byte[] body, byte[] decoded, String message) {
        require(body.length > 0 && body.length <= MAX_ORIGINAL, "Original POST form unavailable");
        var fields = fields(new String(body, StandardCharsets.UTF_8));
        require(fields.keySet().stream().allMatch(k -> Set.of(message, "RelayState").contains(k)) && fields.containsKey(message), "Original POST contains a foreign or credential field");
        try { require(Arrays.equals(Base64.getDecoder().decode(fields.get(message)), decoded), "Raw POST message differs from decoded original"); }
        catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("Raw POST message differs from decoded original"); }
    }

    static Map<String,String> fields(String raw) {
        var result = new LinkedHashMap<String,String>(); require(raw != null && raw.length() <= MAX_ORIGINAL, "Form unavailable or oversized");
        for (String part : raw.split("&", -1)) {
            int equal = part.indexOf('='); require(equal > 0, "Malformed POST field");
            String name = URLDecoder.decode(part.substring(0, equal), StandardCharsets.UTF_8), value = URLDecoder.decode(part.substring(equal + 1), StandardCharsets.UTF_8);
            require(result.putIfAbsent(name, value) == null, "Duplicate POST field");
        }
        return result;
    }

    /** Validates only already irreversible same-Run inbound Response metadata, then omits it in RAM.
     * Neither the stored entry nor any original is rewritten; no header is part of Original.export(). */
    static Map<String,List<String>> nativeHeaderProjection(TranscriptEntry entry, String runId) {
        require(entry != null && runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}") && runId.equals(entry.runId())
                && entry.id() != null && entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")
                && entry.headers() != null && entry.headers().size() <= 128 && entry.samlSummary() != null,
                "Native header Run/row boundary unavailable");
        var names = new HashSet<String>(); var clean = new LinkedHashMap<String,List<String>>();
        for (var field : entry.headers().entrySet()) {
            String name = field.getKey(); require(name != null && HEADER_NAME.matcher(name).matches()
                    && names.add(name.toLowerCase(Locale.ROOT)) && field.getValue() != null && !field.getValue().isEmpty() && field.getValue().size() <= 128
                    && field.getValue().stream().allMatch(v -> v != null && v.length() <= 65536 && v.indexOf('\r') < 0 && v.indexOf('\n') < 0), "Malformed or duplicate header metadata");
            String lower = name.toLowerCase(Locale.ROOT);
            require(!Set.of("authorization", "proxy-authorization", "set-cookie").contains(lower), "Foreign credential header metadata");
            if (lower.equals("cookie")) {
                require(entry.direction() == Direction.INBOUND && "POST".equals(entry.method())
                        && "Response".equals(entry.samlSummary().get("type")) && field.getValue().size() == 1,
                        "Cookie metadata is not one typed same-Run inbound Response");
                var cookieNames = new HashSet<String>();
                for (String cookie : field.getValue().getFirst().split("; ", -1)) {
                    var match = REDACTED_COOKIE.matcher(cookie); require(match.matches() && cookieNames.add(match.group(1)), "Raw, malformed, or duplicate cookie metadata");
                    require(Long.parseLong(match.group(2)) <= MAX_ORIGINAL, "Cookie redaction byte count outside bound");
                }
            } else clean.put(name, List.copyOf(field.getValue()));
        }
        require(noCredentials(clean), "Credential projection incomplete"); return Map.copyOf(clean);
    }

    static List<TranscriptEntry> nativeEntries(Connection db, JsonCodec codec, String runId) throws Exception {
        var entries = new ArrayList<TranscriptEntry>(); var ids = new HashSet<String>();
        try (var query = db.prepareStatement("SELECT id,run_id,document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id LIMIT ?")) {
            query.setString(1, runId); query.setInt(2, MAX_ENTRIES + 1);
            try (var rows = query.executeQuery()) { while (rows.next()) {
                String document = rows.getString(3); require(document != null && document.length() <= MAX_ORIGINAL, "Transcript document exceeds bound");
                var entry = codec.read(document, TranscriptEntry.class);
                require(rows.getString(1).equals(entry.id()) && rows.getString(2).equals(entry.runId()) && runId.equals(entry.runId())
                        && ids.add(entry.id()) && entries.size() < MAX_ENTRIES && entry.samlSummary() != null && entry.timestamp() != null, "Transcript row/Run identity or bound differs");
                var headers = nativeHeaderProjection(entry, runId);
                entries.add(new TranscriptEntry(entry.id(), entry.runId(), entry.direction(), entry.timestamp(), entry.correlationId(), entry.method(), entry.url(), entry.status(),
                        headers, entry.bodyRef(), entry.bodyBytes(), entry.decodedSamlRef(), entry.decodedSamlBytes(), entry.contentType(), entry.rawQuery(), entry.samlSummary()));
            } }
        }
        return List.copyOf(entries);
    }

    static List<OutboxEntry> selectedOutbox(Connection db, JsonCodec codec, String runId) throws Exception {
        var entries = new ArrayList<OutboxEntry>(); var ids = new HashSet<String>();
        try (var query = db.prepareStatement("SELECT action_id,run_id,case_id,action_json,status,send_result_json,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? AND case_id=? ORDER BY action_id LIMIT 4")) {
            query.setString(1, runId); query.setString(2, SELECTED);
            try (var rows = query.executeQuery()) { while (rows.next()) {
                String document = rows.getString(4); require(document != null && document.length() <= 2 * MAX_ORIGINAL, "Selected outbox document exceeds bound");
                var action = codec.read(document, OutboundAction.class);
                require(entries.size() < 3 && rows.getString(1).equals(action.actionId()) && runId.equals(rows.getString(2))
                        && SELECTED.equals(rows.getString(3)) && ids.add(action.actionId()) && action.kind() == OutboundKind.AUTHN_REQUEST
                        && !action.requiresEphemeralCredential() && action.payload().length > 0 && action.payload().length <= MAX_ORIGINAL
                        && publicXml(action.payload()) && action.target().toASCIIString().equals(SSO), "Outbox row identity, public payload, or native target differs");
                Map<String,Object> send = rows.getString(6) == null ? Map.of() : codec.read(rows.getString(6), Map.class);
                entries.add(new OutboxEntry(runId, SELECTED, action, OutboxStatus.valueOf(rows.getString(5)), send, rows.getString(7), Instant.parse(rows.getString(8)), Instant.parse(rows.getString(9))));
            } }
        }
        return List.copyOf(entries);
    }

    static CaseExecution selectedExecution(Connection db, JsonCodec codec, String runId) throws Exception {
        try (var query = db.prepareStatement("SELECT run_id,case_id,document_json FROM case_executions WHERE run_id=? AND case_id=? LIMIT 2")) {
            query.setString(1, runId); query.setString(2, SELECTED);
            try (var rows = query.executeQuery()) {
                require(rows.next(), "Selected execution unavailable"); var execution = codec.read(rows.getString(3), CaseExecution.class);
                require(runId.equals(rows.getString(1)) && SELECTED.equals(rows.getString(2)) && runId.equals(execution.runId())
                        && SELECTED.equals(execution.caseId()) && execution.status() == CaseExecutionStatus.FINISHED && execution.outcome() != null && !rows.next(), "Selected execution identity or finished outcome differs");
                return execution;
            }
        }
    }

    static String boundDocument(Connection db, String table, String id) throws Exception {
        require(Set.of("runs", "plans").contains(table), "Unknown bound document table");
        try (var query = db.prepareStatement("SELECT id,document_json FROM " + table + " WHERE id=? LIMIT 2")) {
            query.setString(1, id); try (var rows = query.executeQuery()) {
                require(rows.next() && id.equals(rows.getString(1)), "Bound Run/Plan row unavailable"); String document = rows.getString(2);
                require(document != null && document.length() <= MAX_ORIGINAL && !rows.next(), "Bound Run/Plan document duplicate or oversized"); return document;
            }
        }
    }

    static int count(Connection db, String table, String runId) throws Exception {
        require(Set.of("case_executions", "outbox_actions", "transcript_entries").contains(table), "Unknown count table");
        try (var query = db.prepareStatement("SELECT COUNT(*) FROM " + table + " WHERE run_id=?")) {
            query.setString(1, runId); try (var rows = query.executeQuery()) {
                require(rows.next(), "Count unavailable"); int count = rows.getInt(1); require(count >= 0 && !rows.next(), "Invalid count"); return count;
            }
        }
    }
}
