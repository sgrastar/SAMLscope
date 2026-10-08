package com.samlscope.api;

import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;
import com.samlscope.core.casedef.*;
import com.samlscope.core.evaluation.CoverageCatalogMapper;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.Direction;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.Connection;
import java.util.*;

/** Bound owned synthetic browser-M0 scope only; reuses reviewed immutable public-file guards. */
public final class ReadSyntheticNormalBrowserScope {
    static final String SELECTED = "IIP-SSO01-f-idp-01";
    static int count(Connection db, String table, String run) throws Exception {
        require(Set.of("case_executions", "outbox_actions", "transcript_entries").contains(table), "Unknown count table");
        try (var query = db.prepareStatement("SELECT COUNT(*) FROM " + table + " WHERE run_id=?")) {
            query.setString(1, run); try (var rows = query.executeQuery()) { require(rows.next(), "Count unavailable"); int value = rows.getInt(1); require(!rows.next(), "Duplicate count"); return value; }
        }
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 4 && args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}") && Set.of("scope", "runtime").contains(args[2]), "Bound synthetic Run and public Suite metadata required");
        Path data = Path.of(args[0]).toAbsolutePath(); require(data.equals(data.normalize()), "Noncanonical root"); rejectSymlinkAncestors(data);
        var codec = new JsonCodec(); var result = new LinkedHashMap<String,Object>();
        try (var db = readOnlyDatabase(data.resolve("samlscope.db"))) {
            var run = codec.read(single(db, "SELECT document_json FROM runs WHERE id=?", args[1]), TestRun.class);
            var plan = codec.read(single(db, "SELECT document_json FROM plans WHERE id=?", run.planId()), TestPlan.class);
            require(run.id().equals(args[1]) && run.planId().equals(plan.id()) && plan.profile() == FunctionalProfile.BROWSER_SSO_IDP
                && plan.name().equals("Synthetic normal browser cold M0; no adoption") && plan.target().kind() == TargetKind.IDP
                && plan.target().entityId().equals("http://host.docker.internal:18936/entity") && plan.definitionIdentity() != null, "Foreign synthetic scope");
            var documents = CatalogDocuments.load(); var releases = FunctionalProfileDocuments.load();
            var resolver = new PinnedFunctionalCaseDefinitionResolver(releases.artifacts(), releases.digests(),
                Map.of("tests/coverage.yaml", documents.bytes("tests/coverage.yaml"), "tests/cases.yaml", documents.bytes("tests/cases.yaml"), "tests/predicates.yaml", documents.bytes("tests/predicates.yaml")),
                CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml")), CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml")));
            var membership = resolver.resolve(plan.definitionIdentity()).cases(); var selected = only(membership.stream().filter(c -> SELECTED.equals(c.id())).toList(), "Actual approved membership");
            int cases = count(db, "case_executions", run.id()), outbox = count(db, "outbox_actions", run.id()), transcriptCount = count(db, "transcript_entries", run.id());
            require(cases == 0 && outbox == 0, "M0 scope contains case executions or outbox actions");
            result.put("schema", "owned-synthetic-normal-browser-native-v1"); result.put("runId", run.id()); result.put("planId", plan.id()); result.put("runStatus", run.status());
            result.put("approvedSelectedCase", selected); result.put("definitionIdentity", plan.definitionIdentity());
            result.put("actualCaseExecutions", cases); result.put("actualOutboxActions", outbox); result.put("transcriptEntries", transcriptCount);
            result.put("databaseAccess", "URI-escaped-mode-ro-query-only"); result.put("privateKeyReads", 0); result.put("canonicalAdoption", false);
            if (args[2].equals("scope")) {
                require(Set.of(RunStatus.CREATED, RunStatus.RUNNING).contains(run.status()) && !run.context().containsKey("authnRequestId") && transcriptCount == 0, "Cold scope already has M0 or transcripts");
            } else {
                require(run.status() == RunStatus.COMPLETED && transcriptCount == 2, "Actual normal M0 incomplete or extra operations");
                var entries = entries(db, codec, run.id()); var originals = new LinkedHashMap<String,ReadSyntheticArtifactRuntime.Original>();
                for (var entry : entries) originals.put(entry.id(), readOriginal(data, entry));
                var request = only(entries.stream().filter(e -> e.direction() == Direction.OUTBOUND && "AuthnRequest".equals(e.samlSummary().get("type"))).toList(), "Normal request");
                var response = only(entries.stream().filter(e -> e.direction() == Direction.INBOUND && Boolean.TRUE.equals(e.samlSummary().get("normalFlowAccepted"))).toList(), "Normal response");
                var authn = saml(originals, request); var reply = saml(originals, response);
                String id = authn.getAttribute("ID"), issuer = single(authn, A, "Issuer").getTextContent();
                byte[] suiteMetadata = publicFile(Path.of(args[3])); var suiteEntity = suiteEntity(suiteMetadata, plan.id(), issuer);
                var suiteCerts = certificates(suiteEntity); byte[] targetMetadata = publicFile(data.resolve("target-metadata").resolve(run.id() + ".xml"));
                var targetCerts = new TargetMetadataParser().parse(targetMetadata, plan.target().entityId()).signingCertificates();
                require(id.equals(run.context().get("authnRequestId")) && id.equals(response.correlationId()) && id.equals(reply.getAttribute("InResponseTo"))
                    && "Response".equals(reply.getLocalName()) && P.equals(reply.getNamespaceURI()) && "2.0".equals(reply.getAttribute("Version"))
                    && plan.target().entityId().equals(single(reply, A, "Issuer").getTextContent()) && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(status(reply))
                    && reply.getAttribute("Destination").equals(authn.getAttribute("AssertionConsumerServiceURL")) && response.url().equals(reply.getAttribute("Destination"))
                    && registeredAcs(suiteEntity, reply.getAttribute("Destination"), POST), "Normal correlation, issuer or ACS differs");
                require(request.rawQuery() != null && suiteCerts.stream().anyMatch(c -> new RedirectSignatureVerifier().isValidForMessage(request.rawQuery(), c, original(originals, request).decoded())), "Actual Redirect signature unproven");
                require(targetCerts.stream().anyMatch(c -> new XmlSignatureVerifier().hasValidEnvelopedSignature(reply, c)), "Response signature unproven");
                var assertion = single(reply, A, "Assertion"); require(targetCerts.stream().anyMatch(c -> new XmlSignatureVerifier().hasValidEnvelopedSignature(assertion, c)), "Assertion signature unproven");
                result.put("authnRequestId", id); result.put("normalRequestReference", request.id()); result.put("normalResponseReference", response.id());
                result.put("requestRedirectSignatureVerified", true); result.put("responseSignatureVerified", true); result.put("assertionSignatureVerified", true);
                result.put("noCredentialOrCookieHeaders", true); result.put("transcriptOriginals", originals.values().stream().map(ReadSyntheticArtifactRuntime.Original::export).toList());
                result.put("suitePublicMetadataSha256", hash(suiteMetadata)); result.put("runMetadataSnapshotSha256", hash(targetMetadata));
            }
        }
        System.out.println(codec.write(result));
    }
}
