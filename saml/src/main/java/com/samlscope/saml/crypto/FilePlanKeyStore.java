package com.samlscope.saml.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.samlscope.saml.normal.SamlException;

public final class FilePlanKeyStore {
    private final Path directory;
    private final Clock clock;

    public FilePlanKeyStore(Path dataDirectory, Clock clock) {
        this.directory = dataDirectory.resolve("keys");
        this.clock = clock;
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new SamlException("Could not create key directory", e);
        }
    }

    public synchronized PlanCredentials getOrCreate(String planId) {
        return getOrCreate(planId, "primary");
    }

    public synchronized PlanCredentials getOrCreate(String planId, String keyAlias) {
        return getOrCreate(planId, keyAlias, false);
    }

    /** An isolated EC signing key; existing RSA and encryption keys keep their paths. */
    public synchronized PlanCredentials getOrCreateEc(String planId, String keyAlias) {
        return getOrCreate(planId, keyAlias, true);
    }

    private PlanCredentials getOrCreate(String planId, String keyAlias, boolean ec) {
        if (keyAlias == null || !keyAlias.matches("[a-z][a-z0-9-]{0,31}")) {
            throw new IllegalArgumentException("Invalid key alias");
        }
        var planDirectory = safePlanDirectory(planId);
        if (!"primary".equals(keyAlias)) planDirectory = planDirectory.resolve(keyAlias);
        if (ec) planDirectory = planDirectory.resolve("ec-p256");
        var keyPath = planDirectory.resolve("signing-key.pk8");
        var certificatePath = planDirectory.resolve("signing-certificate.der");
        try {
            if (!Files.exists(keyPath) || !Files.exists(certificatePath)) {
                Files.createDirectories(planDirectory);
                generate(planId, keyAlias, keyPath, certificatePath, ec);
            }
            var privateKey = KeyFactory.getInstance(ec ? "EC" : "RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyPath)));
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(certificatePath)));
            return new PlanCredentials(privateKey, certificate);
        } catch (Exception e) {
            throw new SamlException("Could not load the Test Plan key", e);
        }
    }

    private void generate(String planId, String keyAlias, Path keyPath, Path certificatePath, boolean ec) throws Exception {
        var generator = KeyPairGenerator.getInstance(ec ? "EC" : "RSA");
        if (ec) generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), new SecureRandom());
        else generator.initialize(3072, new SecureRandom());
        var pair = generator.generateKeyPair();
        var now = clock.instant();
        var name = new X500Name("CN=samlscope " + keyAlias + " test key (DO NOT TRUST),OU="
                + planId + ",O=samlscope");
        var certificateBuilder = new JcaX509v3CertificateBuilder(
                name,
                new BigInteger(160, new SecureRandom()).abs(),
                Date.from(now.minus(Duration.ofDays(1))),
                Date.from(now.plus(Duration.ofDays(365))),
                name,
                pair.getPublic());
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(ec ? KeyUsage.digitalSignature : KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        var signer = new JcaContentSignerBuilder(ec ? "SHA256withECDSA" : "SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(pair.getPrivate());
        var certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(signer));
        Files.write(keyPath, pair.getPrivate().getEncoded());
        restrictPrivateKey(keyPath);
        Files.write(certificatePath, certificate.getEncoded());
    }

    private void restrictPrivateKey(Path keyPath) {
        try {
            Files.setPosixFilePermissions(keyPath, Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX platforms rely on the data-directory ACL.
        }
    }

    private Path safePlanDirectory(String planId) {
        if (planId == null || !planId.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")) {
            throw new IllegalArgumentException("Invalid plan ID");
        }
        return directory.resolve(planId);
    }
}
