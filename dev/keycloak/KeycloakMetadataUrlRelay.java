import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Properties;
import java.util.concurrent.Executors;

/**
 * Transparent, evidence-recording relay for the reference Keycloak metadata URL campaign.
 *
 * <p>The relay never changes metadata bytes.  Each target request either fetches the configured
 * Suite URL or serves one previously captured Suite original.  The controlling process changes
 * only {@code relay.properties}; every request reads that file again.  This keeps the target URL
 * stable while preserving the exact upstream and served bodies as campaign originals.</p>
 */
public final class KeycloakMetadataUrlRelay {
    private static final int MAXIMUM_METADATA_BYTES = 4 * 1024 * 1024;
    private final Path evidence;
    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private long sequence;

    private KeycloakMetadataUrlRelay(Path evidence) throws IOException {
        this.evidence = evidence.toAbsolutePath().normalize();
        Files.createDirectories(this.evidence);
        var counter = this.evidence.resolve("relay-sequence.txt");
        this.sequence = Files.isRegularFile(counter)
                ? Long.parseLong(Files.readString(counter, StandardCharsets.US_ASCII).strip()) : 0L;
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 2) throw new IllegalArgumentException("usage: <evidence-dir> <port>");
        var relay = new KeycloakMetadataUrlRelay(Path.of(arguments[0]));
        var server = HttpServer.create(new InetSocketAddress(Integer.parseInt(arguments[1])), 16);
        server.createContext("/entities/", relay::handle);
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.start();
        Thread.currentThread().join();
    }

    private synchronized void handle(HttpExchange exchange) throws IOException {
        var started = Instant.now();
        var status = 500;
        byte[] upstream = new byte[0];
        byte[] served = new byte[0];
        String mode = "unavailable";
        String entity = "";
        String source = "";
        String failure = "";
        var next = ++sequence;
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                status = 405;
                return;
            }
            var prefix = "/entities/";
            var path = exchange.getRequestURI().getRawPath();
            if (!path.startsWith(prefix)) {
                status = 404;
                return;
            }
            entity = URLDecoder.decode(path.substring(prefix.length()), StandardCharsets.UTF_8);
            var settings = properties();
            mode = required(settings, "mode");
            if (!entity.equals(required(settings, "entityId"))) {
                status = 404;
                return;
            }
            source = required(settings, "sourceUrl");
            if ("fetch".equals(mode)) {
                var uri = URI.create(source);
                if (!"http".equals(uri.getScheme())
                        || !"samlscope-reference-suite".equals(uri.getHost())
                        || uri.getPort() != 8080) {
                    throw new IllegalArgumentException("Suite source URL is not allowlisted");
                }
                var response = client.send(HttpRequest.newBuilder(uri).GET().build(),
                        HttpResponse.BodyHandlers.ofByteArray());
                status = response.statusCode();
                upstream = response.body();
                if (status != 200) return;
                served = upstream;
            } else if ("frozen".equals(mode)) {
                var name = required(settings, "frozenFile");
                var file = evidence.resolve(name).normalize();
                if (!file.getParent().equals(evidence) || !Files.isRegularFile(file)) {
                    throw new IllegalArgumentException("Frozen original is unavailable");
                }
                served = Files.readAllBytes(file);
                upstream = served;
                status = 200;
            } else {
                throw new IllegalArgumentException("Unknown relay mode");
            }
            if (served.length == 0 || served.length > MAXIMUM_METADATA_BYTES) {
                throw new IllegalArgumentException("Metadata body size is invalid");
            }
            Files.write(evidence.resolve("relay-body-" + next + ".xml"), served,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            exchange.getResponseHeaders().set("Content-Type", "application/samlmetadata+xml");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(200, served.length);
            exchange.getResponseBody().write(served);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            failure = interrupted.getClass().getSimpleName();
            status = 502;
        } catch (Exception error) {
            failure = error.getClass().getSimpleName();
            status = 502;
        } finally {
            if (exchange.getResponseCode() < 0) exchange.sendResponseHeaders(status, -1);
            exchange.close();
            Files.writeString(evidence.resolve("relay-sequence.txt"), Long.toString(sequence) + "\n",
                    StandardCharsets.US_ASCII, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            var record = "{" +
                    "\"sequence\":" + next + "," +
                    "\"startedAt\":\"" + json(started.toString()) + "\"," +
                    "\"completedAt\":\"" + json(Instant.now().toString()) + "\"," +
                    "\"method\":\"" + json(exchange.getRequestMethod()) + "\"," +
                    "\"requestPath\":\"" + json(exchange.getRequestURI().getRawPath()) + "\"," +
                    "\"entityId\":\"" + json(entity) + "\"," +
                    "\"mode\":\"" + json(mode) + "\"," +
                    "\"sourceUrl\":\"" + json(source) + "\"," +
                    "\"httpStatus\":" + status + "," +
                    "\"upstreamSha256\":\"" + hash(upstream) + "\"," +
                    "\"servedSha256\":\"" + hash(served) + "\"," +
                    "\"servedFile\":\"relay-body-" + next + ".xml\"," +
                    "\"failure\":\"" + json(failure) + "\"}\n";
            Files.writeString(evidence.resolve("relay-requests.jsonl"), record,
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND, StandardOpenOption.WRITE);
        }
    }

    private Properties properties() throws IOException {
        var values = new Properties();
        try (var input = Files.newInputStream(evidence.resolve("relay.properties"))) {
            values.load(input);
        }
        return values;
    }

    private static String required(Properties values, String name) {
        var value = values.getProperty(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + name);
        return value;
    }

    private static String hash(byte[] raw) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
