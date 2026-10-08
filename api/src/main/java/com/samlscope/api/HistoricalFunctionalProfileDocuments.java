package com.samlscope.api;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.casedef.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.profile.*;
import com.samlscope.runner.*;
import com.samlscope.runner.result.EvaluationArtifactDigests;
import java.io.*;
import java.util.*;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/** Fixed public C/A resources. This loader is connected only after independent composition review. */
final class HistoricalFunctionalProfileDocuments {
    static final String SOURCE_C = "064df1c2c49d8f4e2b718c056970f06562c40f4e";
    static final String APPROVAL_A = "769b93a9a40bb392277ecc6f3dc0b4dfc18c5c9b";
    static final String BASE = "/META-INF/samlscope/profile-history/" + SOURCE_C + "/";
    static final String MANIFEST_SHA = "sha256:1e9c8bfb902ffaced1720b60d0b4e6590df04cc1838b467a1ba395d810e1f2f3";
    static final Map<String,String> PINS = Map.ofEntries(
            Map.entry("tests/coverage.yaml", "sha256:2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c"),
            Map.entry("tests/cases.yaml", "sha256:431d9aa863d5d882d37266667a8fd20547d1fe6d037274b8d59ff66347f5ecd4"),
            Map.entry("tests/predicates.yaml", "sha256:ea0aec770d743d0c8315c706ae80fb5979a103021ebdc4fcf86187c052e90262"),
            Map.entry("tests/specs.yaml", "sha256:acee5ce8c348fbc5e02f77bd2f5b8703a632dd69aea857b14b97812ff6cc39d9"),
            Map.entry("tests/approvals/g1.yaml", "sha256:198d8cabd1b6468b2bc88ad61dcf24f2141a8b80c2b285a51d7cc02691197818"),
            Map.entry("tests/approvals/g2.yaml", "sha256:3a391cbce4f354e32d19057c4af5538fd3f1bf9c60b54c0ec8deb9a22f960ea3"),
            Map.entry("tests/feasibility.yaml", "sha256:b18ee0e940fafc841a6b0aada0000294d64e17099b0ba2a5ad03e4e829820b41"),
            Map.entry("tests/mutants/baselines.yaml", "sha256:87c7ec91c4ae47e40b6b38f3e9bf5bcf9f4253539fa80fa40cc37ff7b7cfdc18"),
            Map.entry("tests/mutants/catalog.yaml", "sha256:3051113742c6396086f87682291f87c0d31449789f0c65a573e1b765135c667f"),
            Map.entry("tests/mutants/control-mutants.yaml", "sha256:a918bf462b959e8f9bcaf3a7fe0abc8eee4e80f20bd5121ebb88c5ceee894208"),
            Map.entry("profiles/release-pins.properties", "sha256:f909640ddee14ae3a09328e8c52e411e1203c5e4415771c042a9119f1b50a6e9"),
            Map.entry("profiles/browser_sso_idp.json", "sha256:8841ab92288146c657efb5f3df5ded60970c890448459f0a80fd141eb7fd5c5f"),
            Map.entry("profiles/browser_sso_sp.json", "sha256:159c8e15f6a3e06b434d2e2464c75d40829ed8f54b0de23e1b1f4d566aa3228b"),
            Map.entry("profiles/ecp_idp.json", "sha256:f930459e44962ea682d00fc4b8efac5440682ddb550da4ac54c114d523281d5e"),
            Map.entry("profiles/metadata_idp.json", "sha256:5b1e904ef9b19bc6267bca6d54f44e9ea06dcd76acb35dad39cb1b1a5f1198fd"),
            Map.entry("profiles/metadata_sp.json", "sha256:3deeb97b95062dec6670aa5b5211a1c9b26406b28283047cf87788dba426dc93"),
            Map.entry("profiles/single_logout_idp.json", "sha256:0158baceb4c032f36c8a9fdbeb89916163a3b61ae567e898b5cd6ed6df06f846"),
            Map.entry("profiles/single_logout_sp.json", "sha256:4d8d77c4e0d22d69d6e44c2b896b4c4df45c46d2486311d4b519ae1ce9ebb92a"));
    private static final int MAX_FILE = 16 * 1024 * 1024;
    @FunctionalInterface interface Resources { byte[] read(String resource) throws IOException; }
    private HistoricalFunctionalProfileDocuments() {}

    // Only fixed installed C/A models are memoized. Every use still verifies all original bytes.
    private static Installed installed;
    private record Models(CaseDefinitionCatalog cases, CoverageCatalog coverage, PredicateCatalog predicates,
                          FunctionalReleaseContext.SourceInventory inventory) {}
    private record Installed(List<FunctionalReleaseContext> releases, Map<FunctionalProfile,byte[]> artifacts) {}

    private static byte[] classpathResource(String resource) throws IOException {
        try (var stream = HistoricalFunctionalProfileDocuments.class.getResourceAsStream(resource)) {
            if (stream == null) throw new IOException("Installed historical resource missing");
            byte[] bytes = stream.readNBytes(MAX_FILE + 1);
            if (bytes.length > MAX_FILE) throw new IOException("Installed historical resource too large");
            return bytes;
        }
    }
    static List<FunctionalReleaseContext> load() {
        return installed(verify(HistoricalFunctionalProfileDocuments::classpathResource),null).releases();
    }
    static List<FunctionalReleaseContext> load(FunctionalProfileDocuments.Bundle bundle, CatalogDocuments documents,
            CaseDefinitionCatalog cases, CoverageCatalog coverage, PredicateCatalog predicates) {
        var originals = verify(HistoricalFunctionalProfileDocuments::classpathResource);
        return installedWithCurrent(originals,bundle,documents,cases,coverage,predicates).releases();
    }
    /** Injectable readers never use installed memoization; malformed or changed bytes are fresh inputs. */
    static List<FunctionalReleaseContext> load(Resources resources) {
        return parse(verify(resources),null).releases();
    }
    private static synchronized Installed installed(Map<String,byte[]> originals, Models existing) {
        if (installed == null) installed = parse(originals,existing);
        return installed;
    }
    private static synchronized Installed installedWithCurrent(Map<String,byte[]> originals,
            FunctionalProfileDocuments.Bundle bundle, CatalogDocuments documents,
            CaseDefinitionCatalog cases, CoverageCatalog coverage, PredicateCatalog predicates) {
        if (installed == null) {
            var sources = sourceBytes(documents);
            Models existing = currentMatchesOriginals(bundle,sources,originals)
                    ? new Models(cases,coverage,predicates,new FunctionalReleaseContext.SourceInventory(sources)) : null;
            installed = parse(originals,existing);
        }
        return installed;
    }

    private static Map<String,byte[]> verify(Resources resources) {
        try {
            byte[] manifestBytes = bounded(resources.read(BASE + "manifest.json"));
            require(MANIFEST_SHA.equals(EvaluationArtifactDigests.digestBytes(manifestBytes)),"Historical manifest differs from closed release pin");
            var manifest = json(manifestBytes);
            require(manifest.keySet().equals(Set.of("schema","sourceCommit","approvalCommit","files"))
                    && "samlscope-installed-historical-profile-bundle-v1".equals(manifest.get("schema"))
                    && SOURCE_C.equals(manifest.get("sourceCommit")) && APPROVAL_A.equals(manifest.get("approvalCommit")),"Historical manifest authority differs");
            var declarations = object(manifest.get("files"));
            require(PINS.keySet().equals(declarations.keySet()),"Historical resource inventory differs");
            var originals = new LinkedHashMap<String,byte[]>();
            for (var path : PINS.keySet()) {
                var declaration = object(declarations.get(path));
                require(declaration.keySet().equals(Set.of("sha256","bytes","sourceRevision"))
                        && PINS.get(path).equals(declaration.get("sha256"))
                        && ("tests/approvals/g2.yaml".equals(path) ? APPROVAL_A : SOURCE_C).equals(declaration.get("sourceRevision")),"Historical blob authority differs");
                byte[] original = bounded(resources.read(BASE + path));
                require(declaration.get("bytes") instanceof Number size && size.longValue() == original.length
                        && PINS.get(path).equals(EvaluationArtifactDigests.digestBytes(original)),"Historical blob bytes differ");
                originals.put(path,original);
            }
            var approval = yaml(originals.get("tests/approvals/g2.yaml"));
            require(SOURCE_C.equals(approval.get("target_commit")),"Historical G2 approval names another source");
            return Collections.unmodifiableMap(originals);
        } catch (IOException | RuntimeException unavailable) {
            throw new IllegalStateException("Installed signed historical definition resources are invalid",unavailable);
        }
    }
    private static Installed parse(Map<String,byte[]> originals, Models existing) {
        try {
            var sources = new LinkedHashMap<String,byte[]>();
            FunctionalReleaseContext.SOURCE_PATHS.forEach(path -> sources.put(path,originals.get(path)));
            var models = existing != null ? existing : new Models(
                    CaseDefinitionCatalogMapper.fromDocument(yaml(originals.get("tests/cases.yaml"))),
                    CoverageCatalogMapper.fromDocument(yaml(originals.get("tests/coverage.yaml"))),
                    PredicateCatalogMapper.fromDocument(yaml(originals.get("tests/predicates.yaml"))),
                    new FunctionalReleaseContext.SourceInventory(sources));
            var profileSources = Map.of("tests/coverage.yaml",sources.get("tests/coverage.yaml"),
                    "tests/cases.yaml",sources.get("tests/cases.yaml"),"tests/predicates.yaml",sources.get("tests/predicates.yaml"));
            var pins = new Properties(); pins.load(new ByteArrayInputStream(originals.get("profiles/release-pins.properties")));
            require(pins.stringPropertyNames().equals(Arrays.stream(FunctionalProfile.values()).map(FunctionalProfile::id).collect(java.util.stream.Collectors.toSet())),"Historical active profile pins differ");
            var releases = new ArrayList<FunctionalReleaseContext>();var artifacts = new EnumMap<FunctionalProfile,byte[]>(FunctionalProfile.class);
            for (var profile : FunctionalProfile.values()) {
                byte[] artifact = originals.get("profiles/"+profile.id()+".json");artifacts.put(profile,artifact);
                String digest = EvaluationArtifactDigests.digestBytes(artifact);
                require(digest.equals(pins.getProperty(profile.id())),"Historical profile release pin differs");
                var definition = FunctionalCaseDefinitionLoader.load(json(artifact),profileSources,models.cases(),models.coverage());
                require(definition.profile() == profile,"Historical profile role differs");
                releases.add(new FunctionalReleaseContext(new FunctionalDefinitionIdentity(profile,definition.version(),digest),
                        definition,models.cases(),models.coverage(),models.predicates(),models.inventory(),FunctionalReleaseContext.Kind.HISTORICAL,SOURCE_C));
            }
            return new Installed(List.copyOf(releases),Collections.unmodifiableMap(artifacts));
        } catch (IOException | RuntimeException unavailable) {
            throw new IllegalStateException("Installed signed historical definition resources are invalid",unavailable);
        }
    }
    private static Map<String,byte[]> sourceBytes(CatalogDocuments documents) {
        var sources = new LinkedHashMap<String,byte[]>();
        FunctionalReleaseContext.SOURCE_PATHS.forEach(path -> sources.put(path,documents.bytes(path)));
        return sources;
    }
    private static boolean currentMatchesOriginals(FunctionalProfileDocuments.Bundle bundle,
            Map<String,byte[]> sources,Map<String,byte[]> originals) {
        return bundle.artifacts().keySet().equals(bundle.digests().keySet())
                && FunctionalReleaseContext.SOURCE_PATHS.equals(sources.keySet())
                && sources.entrySet().stream().allMatch(e->Arrays.equals(e.getValue(),originals.get(e.getKey())))
                && bundle.artifacts().keySet().equals(Set.of(FunctionalProfile.values()))
                && bundle.artifacts().entrySet().stream().allMatch(e->Arrays.equals(e.getValue(),originals.get("profiles/"+e.getKey().id()+".json")))
                && bundle.artifacts().entrySet().stream().allMatch(e->EvaluationArtifactDigests.digestBytes(e.getValue()).equals(bundle.digests().get(e.getKey())));
    }
    static List<FunctionalReleaseContext> current(FunctionalProfileDocuments.Bundle bundle, CatalogDocuments documents) {
        return current(bundle,documents,CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml")),
                CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml")),
                PredicateCatalogMapper.fromDocument(documents.parsed("tests/predicates.yaml")));
    }
    static List<FunctionalReleaseContext> current(FunctionalProfileDocuments.Bundle bundle, CatalogDocuments documents,
            CaseDefinitionCatalog cases, CoverageCatalog coverage, PredicateCatalog predicates) {
        var sources = sourceBytes(documents);
        Installed retained; synchronized(HistoricalFunctionalProfileDocuments.class) { retained = installed; }
        if (retained != null && bundle.artifacts().keySet().equals(bundle.digests().keySet())
                && retained.releases().getFirst().sourceInventory().matches(sources)
                && bundle.artifacts().keySet().equals(retained.artifacts().keySet())
                && bundle.artifacts().entrySet().stream().allMatch(e->Arrays.equals(e.getValue(),retained.artifacts().get(e.getKey()))
                    && EvaluationArtifactDigests.digestBytes(e.getValue()).equals(bundle.digests().get(e.getKey())))) {
            return retained.releases().stream().map(old->new FunctionalReleaseContext(old.identity(),old.definition(),
                    old.cases(),old.coverage(),old.predicates(),old.sourceInventory(),FunctionalReleaseContext.Kind.CURRENT,null)).toList();
        }
        var inventory = new FunctionalReleaseContext.SourceInventory(sources);
        var resolver = new PinnedFunctionalCaseDefinitionResolver(bundle.artifacts(),bundle.digests(),Map.of(
                "tests/coverage.yaml",sources.get("tests/coverage.yaml"),"tests/cases.yaml",sources.get("tests/cases.yaml"),
                "tests/predicates.yaml",sources.get("tests/predicates.yaml")),cases,coverage);
        return resolver.profiles().stream().map(profile -> new FunctionalReleaseContext(resolver.identity(profile),
                resolver.resolve(resolver.identity(profile)),cases,coverage,predicates,inventory,
                FunctionalReleaseContext.Kind.CURRENT,null)).toList();
    }

    static byte[] bounded(byte[] bytes) {
        require(bytes != null && bytes.length > 0 && bytes.length <= MAX_FILE,"Historical resource unavailable or oversized");
        return bytes.clone();
    }
    static Map<String,Object> json(byte[] bytes) throws IOException {
        return new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readValue(bytes,new TypeReference<Map<String,Object>>() {});
    }
    static Map<String,Object> yaml(byte[] bytes) {
        var options = new LoaderOptions(); options.setAllowDuplicateKeys(false); options.setMaxAliasesForCollections(1000);
        options.setCodePointLimit(MAX_FILE);
        return object(new Yaml(new SafeConstructor(options)).load(new ByteArrayInputStream(bytes)));
    }
    static Map<String,Object> object(Object value) {
        require(value instanceof Map<?,?>,"Historical document is not an object");
        var result = new LinkedHashMap<String,Object>();
        ((Map<?,?>)value).forEach((key,child) -> { require(key instanceof String,"Historical object key is not text");result.put((String)key,child); });
        return result;
    }
    static void require(boolean value,String reason) { if (!value) throw new IllegalArgumentException(reason); }
}
