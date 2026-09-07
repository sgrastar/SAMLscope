package com.samlscope.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.StandardOpenOption;

public final class MetadataCache {
    private final Path directory;

    public MetadataCache(Path dataDirectory) {
        this.directory = dataDirectory.resolve("target-metadata");
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new StoreException("Could not create metadata cache", e);
        }
    }

    public void put(String planId, byte[] metadata) {
        try {
            Files.write(path(planId), metadata);
        } catch (IOException e) {
            throw new StoreException("Could not cache target metadata", e);
        }
    }

    /** Writes a Run-scoped evidence snapshot exactly once; later preflight runs cannot replace it. */
    public synchronized void putIfAbsent(String runId, byte[] metadata) {
        try {
            Files.write(path(runId), metadata, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException alreadySnapshotted) {
            // The first successful preflight owns the immutable Run evidence.
        } catch (IOException e) {
            throw new StoreException("Could not snapshot target metadata", e);
        }
    }

    public byte[] get(String planId) {
        try {
            return Files.readAllBytes(path(planId));
        } catch (java.nio.file.NoSuchFileException e) {
            throw new MetadataUnavailable();
        } catch (IOException e) {
            throw new StoreException("Target metadata is not cached for plan " + planId, e);
        }
    }

    public static final class MetadataUnavailable extends RuntimeException {
        public MetadataUnavailable() { super("Target metadata requires a successful preflight"); }
    }

    /**
     * Returns the immutable Run snapshot, migrating a pre-snapshot Run from its Plan cache once.
     * The fallback exists only for Runs created by older SAMLscope versions; subsequent reads are
     * always bound to the Run path even if the Plan metadata is refreshed later.
     */
    public synchronized byte[] getRunSnapshot(String runId, String planId) {
        if (!Files.exists(path(runId))) putIfAbsent(runId, get(planId));
        return get(runId);
    }

    private Path path(String planId) {
        if (!planId.matches("[a-z]+_[0-9A-HJKMNP-TV-Z]{26}")) {
            throw new IllegalArgumentException("Invalid plan ID");
        }
        return directory.resolve(planId + ".xml");
    }
}
