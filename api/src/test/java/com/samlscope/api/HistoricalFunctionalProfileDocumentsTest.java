package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.profile.*;
import com.samlscope.runner.*;
import java.util.*;
import java.io.*;
import org.junit.jupiter.api.Test;

class HistoricalFunctionalProfileDocumentsTest {
    @Test void retainsAllSevenExactSignedOldIdentitiesAndCatalogs() {
        var releases = HistoricalFunctionalProfileDocuments.load();
        assertEquals(7,releases.size());
        var browser = releases.stream().filter(r->r.identity().profile()==FunctionalProfile.BROWSER_SSO_IDP).findFirst().orElseThrow();
        assertEquals("sha256:8841ab92288146c657efb5f3df5ded60970c890448459f0a80fd141eb7fd5c5f",browser.identity().digest());
        assertEquals("sha256:eac0ed91cf492475301d9a3ea651749ad9cf0228a240fb918497b170e6ba4fca",browser.cases().require("IIP-IDP10-d-idp-01").caseDigest());
        assertEquals(FunctionalReleaseContext.Kind.HISTORICAL,browser.kind());
        assertEquals(HistoricalFunctionalProfileDocuments.SOURCE_C,browser.sourceCommit().orElseThrow());
        var variant = browser.cases().require("IIP-IDP10-d-idp-01").variantPlan().stream().filter(v->v.reference().equals("IIP-IDP10.d#v-e2c03ed209")).findFirst().orElseThrow();
        assertEquals("Specify SPNameQualifier; returned NameID/@SPNameQualifier equals the specified value.",variant.instructionEn());
        assertEquals(browser.sourceDigests().get("tests/coverage.yaml"),browser.components().coverageYaml());
    }
    @Test void onlyTheClosedEighteenBlobInventoryIsReadAndEveryTamperIsRejected() throws Exception {
        var originals = originalResources(); var seen = new HashSet<String>();
        assertEquals(7,HistoricalFunctionalProfileDocuments.load(path->{seen.add(path);return originals.get(path);}).size());
        assertEquals(originals.keySet(),seen); assertEquals(19,seen.size());
        for (var path : HistoricalFunctionalProfileDocuments.PINS.keySet()) {
            var changed = originals.get(HistoricalFunctionalProfileDocuments.BASE+path).clone(); changed[changed.length-1]^=1;
            assertThrows(IllegalStateException.class,()->HistoricalFunctionalProfileDocuments.load(resource->
                    resource.equals(HistoricalFunctionalProfileDocuments.BASE+path)?changed:originals.get(resource)),path);
        }
    }
    @Test void forgedSourceOrPrivatePathManifestNeverExpandsTheResourceAuthority() throws Exception {
        var originals = originalResources(); var reads = new ArrayList<String>();
        byte[] forged = "{\"sourceCommit\":\"caller-claimed-source\",\"files\":{\"private/token\":{}}}".getBytes();
        assertThrows(IllegalStateException.class,()->HistoricalFunctionalProfileDocuments.load(path->{reads.add(path);return forged;}));
        assertEquals(List.of(HistoricalFunctionalProfileDocuments.BASE+"manifest.json"),reads);
        assertThrows(IllegalStateException.class,()->HistoricalFunctionalProfileDocuments.load(path->
                path.endsWith("manifest.json")?null:originals.get(path)));
    }
    @Test void duplicateAndTrailingParsedDocumentsCannotBeAccepted() {
        assertThrows(IOException.class,()->HistoricalFunctionalProfileDocuments.json("{\"schema\":1,\"schema\":2}".getBytes()));
        assertThrows(IOException.class,()->HistoricalFunctionalProfileDocuments.json("{} {}".getBytes()));
        assertThrows(RuntimeException.class,()->HistoricalFunctionalProfileDocuments.yaml("a: 1\na: 2\n".getBytes()));
    }
    @Test void currentProfileAuthoritiesStayUnchangedWhenOldBundleIsRetained() {
        var current = HistoricalFunctionalProfileDocuments.current(FunctionalProfileDocuments.load(),CatalogDocuments.load());
        var releases = new FunctionalReleaseRegistry(current,HistoricalFunctionalProfileDocuments.load());
        for (var release : current) {
            assertEquals(release.identity(),releases.identity(release.identity().profile()));
            assertEquals(FunctionalReleaseContext.Kind.CURRENT,releases.require(release.identity()).kind());
            assertEquals(release.sourceDigests(),releases.require(release.identity()).sourceDigests());
        }
        var currentBrowser = releases.require(releases.identity(FunctionalProfile.BROWSER_SSO_IDP));
        assertEquals("sha256:a02075559dff2bf93b50bcc17a601f9037093d5405a9ee93ff5f7f0e80fa346a",currentBrowser.cases().require("IIP-IDP10-d-idp-01").caseDigest());
        var retainedBrowser = HistoricalFunctionalProfileDocuments.load().stream()
                .filter(r->r.identity().profile()==FunctionalProfile.BROWSER_SSO_IDP).findFirst().orElseThrow();
        assertEquals("sha256:eac0ed91cf492475301d9a3ea651749ad9cf0228a240fb918497b170e6ba4fca",releases.require(retainedBrowser.identity()).cases().require("IIP-IDP10-d-idp-01").caseDigest());
        assertEquals(FunctionalReleaseContext.Kind.HISTORICAL,releases.require(retainedBrowser.identity()).kind());
        assertNotEquals(currentBrowser.identity(),retainedBrowser.identity());
    }
    @Test void installedModelsAndSourcesAreSharedButInjectedResourcesRemainFreshAndTamperRejecting() throws Exception {
        var first = HistoricalFunctionalProfileDocuments.load();var second = HistoricalFunctionalProfileDocuments.load();
        assertSame(first,second);
        for(var release:first){assertSame(first.getFirst().sourceInventory(),release.sourceInventory());
            assertSame(first.getFirst().cases(),release.cases());assertSame(first.getFirst().coverage(),release.coverage());}
        var originals = originalResources();
        var fresh = HistoricalFunctionalProfileDocuments.load(originals::get);
        assertNotSame(first.getFirst().cases(),fresh.getFirst().cases());
        byte[] exposed=first.getFirst().sourceBytes("tests/cases.yaml");exposed[0]^=1;
        assertEquals(HistoricalFunctionalProfileDocuments.PINS.get("tests/cases.yaml"),second.getFirst().sourceDigests().get("tests/cases.yaml"));
        var changed=originals.get(HistoricalFunctionalProfileDocuments.BASE+"tests/cases.yaml");changed[0]^=1;
        assertThrows(IllegalStateException.class,()->HistoricalFunctionalProfileDocuments.load(originals::get));
        assertSame(first,HistoricalFunctionalProfileDocuments.load());
    }

    @Test void warmCurrentReleaseKeepsReviewedCatalogSeparateFromRetainedInputsAndRejectsAlteredPins() throws Exception {
        var retained=HistoricalFunctionalProfileDocuments.load();var bundle=FunctionalProfileDocuments.load();var documents=CatalogDocuments.load();
        var matching=HistoricalFunctionalProfileDocuments.current(bundle,documents);
        assertNotSame(retained.getFirst().sourceInventory(),matching.getFirst().sourceInventory());
        assertNotEquals(retained.getFirst().sourceDigests(),matching.getFirst().sourceDigests());
        var currentBrowser=matching.stream().filter(r->r.identity().profile()==FunctionalProfile.BROWSER_SSO_IDP).findFirst().orElseThrow();
        assertEquals("sha256:a02075559dff2bf93b50bcc17a601f9037093d5405a9ee93ff5f7f0e80fa346a",currentBrowser.cases().require("IIP-IDP10-d-idp-01").caseDigest());
        var wrongPins=new HashMap<FunctionalProfile,String>(bundle.digests());wrongPins.put(null,"sha256:"+"a".repeat(64));
        assertThrows(IllegalArgumentException.class,()->HistoricalFunctionalProfileDocuments.current(new FunctionalProfileDocuments.Bundle(bundle.artifacts(),wrongPins),documents));
        var artifacts=new EnumMap<FunctionalProfile,byte[]>(FunctionalProfile.class);artifacts.putAll(bundle.artifacts());
        var pins=new EnumMap<FunctionalProfile,String>(FunctionalProfile.class);pins.putAll(bundle.digests());
        var profile=FunctionalProfile.BROWSER_SSO_IDP;var mapper=new com.fasterxml.jackson.databind.ObjectMapper();
        var changed=mapper.readTree(artifacts.get(profile));((com.fasterxml.jackson.databind.node.ObjectNode)changed).put("version","changed-valid-input");
        byte[] newBytes=mapper.writeValueAsBytes(changed);artifacts.put(profile,newBytes);pins.put(profile,com.samlscope.runner.result.EvaluationArtifactDigests.digestBytes(newBytes));
        var current=HistoricalFunctionalProfileDocuments.current(new FunctionalProfileDocuments.Bundle(artifacts,pins),documents);
        var browser=current.stream().filter(r->r.identity().profile()==profile).findFirst().orElseThrow();
        assertEquals("changed-valid-input",browser.identity().version());assertEquals(pins.get(profile),browser.identity().digest());
        assertNotSame(retained.getFirst().sourceInventory(),browser.sourceInventory());
        for(var release:current)assertSame(current.getFirst().sourceInventory(),release.sourceInventory());
        assertEquals(HistoricalFunctionalProfileDocuments.SOURCE_C,retained.getFirst().sourceCommit().orElseThrow());
    }

    static Map<String,byte[]> originalResources() throws Exception {
        var values = new LinkedHashMap<String,byte[]>();
        var paths = new ArrayList<>(HistoricalFunctionalProfileDocuments.PINS.keySet()); paths.add("manifest.json");
        for (var path : paths) {
            String resource=HistoricalFunctionalProfileDocuments.BASE+path;
            try(var stream=HistoricalFunctionalProfileDocumentsTest.class.getResourceAsStream(resource)) {
                assertNotNull(stream); values.put(resource,stream.readAllBytes());
            }
        }
        return values;
    }
}
