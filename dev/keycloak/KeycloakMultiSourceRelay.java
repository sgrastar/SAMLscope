import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Minimal evidence relay for two immutable MD03.d/MD06.b metadata originals. */
public final class KeycloakMultiSourceRelay {
    private final Path root;
    private final Map<String, Path> sources;

    private KeycloakMultiSourceRelay(Path root, Map<String, Path> sources) {
        this.root = root;
        this.sources = sources;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("root mapping.tsv port");
        Path root = Path.of(args[0]).toRealPath();
        var sources = new LinkedHashMap<String, Path>();
        for (String line : Files.readAllLines(root.resolve(args[1]), StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            String[] values = line.split("\\t", -1);
            if (values.length != 2 || sources.putIfAbsent(values[0], root.resolve(values[1]).normalize()) != null) {
                throw new IllegalArgumentException("invalid relay mapping");
            }
        }
        if (sources.size() != 2 || sources.values().stream().anyMatch(path -> !path.startsWith(root) || !Files.isRegularFile(path))) {
            throw new IllegalArgumentException("relay requires exactly two in-root sources");
        }
        var relay = new KeycloakMultiSourceRelay(root, sources);
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", Integer.parseInt(args[2])), 0);
        server.createContext("/entities/", relay::serve);
        server.start();
    }

    private void serve(HttpExchange exchange) throws IOException {
        int status = 404;
        byte[] body = new byte[0];
        String prefix = "/entities/";
        String entity = "";
        try {
            String path = exchange.getRequestURI().getRawPath();
            if ("GET".equals(exchange.getRequestMethod()) && path.startsWith(prefix)) {
                entity = URLDecoder.decode(path.substring(prefix.length()), StandardCharsets.UTF_8);
                Path source = sources.get(entity);
                if (source != null) {
                    body = Files.readAllBytes(source);
                    status = 200;
                    exchange.getResponseHeaders().set("Content-Type", "application/samlmetadata+xml");
                }
            }
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
        } finally {
            exchange.close();
            String record = "{\"entityId\":\"" + escape(entity) + "\",\"httpStatus\":" + status
                    + ",\"responseSha256\":\"" + sha(body) + "\",\"observedAt\":\""
                    + Instant.now() + "\"}\n";
            synchronized (this) {
                Files.writeString(root.resolve("relay-requests.jsonl"), record, StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            }
        }
    }

    private static String sha(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
