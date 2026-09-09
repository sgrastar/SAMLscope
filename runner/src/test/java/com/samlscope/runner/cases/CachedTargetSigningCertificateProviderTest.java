package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.store.MetadataCache;

class CachedTargetSigningCertificateProviderTest {
    private static final String PLAN_ID = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    @TempDir java.nio.file.Path directory;

    @Test
    void resolvesTheCertificateFromTheCachedTargetEntity() throws Exception {
        var certificate = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC))
                .getOrCreate(PLAN_ID).certificate();
        var encoded = Base64.getEncoder().encodeToString(certificate.getEncoded());
        var metadata = ("""
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example/entity">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>
                      <ds:X509Certificate>%s</ds:X509Certificate>
                    </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
                    <md:SingleSignOnService Binding="urn:test" Location="https://idp.example/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """).formatted(encoded).getBytes(StandardCharsets.UTF_8);
        var cache = new MetadataCache(directory);
        cache.put(PLAN_ID, metadata);
        var provider = new CachedTargetSigningCertificateProvider(cache, new TargetMetadataParser());

        cache.putIfAbsent("run_0123456789ABCDEFGHJKMNPQRS", metadata);
        assertEquals(java.util.List.of(certificate), provider.certificatesFor(
                plan(), "run_0123456789ABCDEFGHJKMNPQRS"));
    }

    private TestPlan plan() {
        return new TestPlan(
                PLAN_ID, "Cached cert", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }
}
