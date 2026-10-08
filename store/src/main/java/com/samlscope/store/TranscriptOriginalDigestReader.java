package com.samlscope.store;

import com.samlscope.core.transcript.TranscriptEntry;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/** Recomputes a digest of a bounded, Run-bound public SAML original without exposing its bytes. */
public final class TranscriptOriginalDigestReader {
    private static final String SCHEMA = "samlscope-transcript-original-digest-v1";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final int MAXIMUM_BYTES = 4 * 1024 * 1024;
    private static final Set<String> TYPES = Set.of("AuthnRequest", "Response", "LogoutRequest", "LogoutResponse",
            "ArtifactResolve", "ArtifactResponse");

    private final SqliteDatabase database;
    private final JsonCodec json;
    private final Path dataDirectory;

    public TranscriptOriginalDigestReader(SqliteDatabase database, JsonCodec json, Path dataDirectory) {
        this.database = Objects.requireNonNull(database);
        this.json = Objects.requireNonNull(json);
        this.dataDirectory = Objects.requireNonNull(dataDirectory).toAbsolutePath().normalize();
    }

    public record Digest(String schema, String runId, String txId,
            String decodedSamlSha256, long decodedSamlBytes) {}

    public Digest read(String runId, String txId) {
        try {
            require(runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                    && txId != null && txId.matches("tx_[0-9A-HJKMNP-TV-Z]{26}"));
            var entry = recordedEntry(runId, txId);
            require(runId.equals(entry.runId()) && txId.equals(entry.id()));
            var reference = "transcripts/" + runId + "/" + txId + ".saml.xml";
            require(reference.equals(entry.decodedSamlRef())
                    && entry.decodedSamlBytes() > 0 && entry.decodedSamlBytes() <= MAXIMUM_BYTES);
            var type = entry.samlSummary() == null ? null : entry.samlSummary().get("type");
            require(type instanceof String && TYPES.contains(type));

            var path = dataDirectory.resolve(reference);
            refuseSymlinks(path);
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(path) == entry.decodedSamlBytes());
            byte[] bytes;
            try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
                bytes = input.readNBytes(entry.decodedSamlBytes() + 1);
            }
            refuseSymlinks(path);
            require(bytes.length == entry.decodedSamlBytes()
                    && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(path) == entry.decodedSamlBytes());
            verifyPublicSaml(bytes, (String) type);
            var digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            return new Digest(SCHEMA, runId, txId, digest, bytes.length);
        } catch (Exception unavailable) {
            // Neither parser diagnostics, database errors, paths nor original content cross this boundary.
            throw new Unavailable();
        }
    }

    private TranscriptEntry recordedEntry(String runId, String txId) throws Exception {
        try (var connection = database.open()) {
            try (var pragma = connection.createStatement()) {
                pragma.execute("PRAGMA query_only = ON");
            }
            try (var select = connection.prepareStatement(
                    "SELECT document_json FROM transcript_entries WHERE run_id = ? AND id = ?")) {
                select.setString(1, runId);
                select.setString(2, txId);
                try (var rows = select.executeQuery()) {
                    require(rows.next());
                    var entry = json.read(rows.getString(1), TranscriptEntry.class);
                    require(entry != null && !rows.next());
                    return entry;
                }
            }
        }
    }

    private static void refuseSymlinks(Path path) {
        for (var current = path; current != null; current = current.getParent()) {
            require(!Files.isSymbolicLink(current));
        }
    }

    private static void verifyPublicSaml(byte[] bytes, String type) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        var builder = factory.newDocumentBuilder();
        builder.setEntityResolver((publicId, systemId) -> { throw new SAXException("Unavailable"); });
        builder.setErrorHandler(new DefaultHandler() {
            @Override public void warning(SAXParseException error) throws SAXException { throw error; }
            @Override public void error(SAXParseException error) throws SAXException { throw error; }
            @Override public void fatalError(SAXParseException error) throws SAXException { throw error; }
        });
        var root = builder.parse(new ByteArrayInputStream(bytes)).getDocumentElement();
        require(root != null && PROTOCOL.equals(root.getNamespaceURI()) && type.equals(root.getLocalName()));
    }

    private static void require(boolean condition) {
        if (!condition) throw new Unavailable();
    }

    public static final class Unavailable extends RuntimeException {
        public Unavailable() { super("Transcript original digest is unavailable"); }
    }
}
