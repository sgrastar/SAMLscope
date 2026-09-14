package com.samlscope.runner;

import java.security.PublicKey;
import java.time.Clock;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.SupplementalDecryptionKeys;
import com.samlscope.store.SqliteSupplementalDecryptionKeys;

/** Run-bound supplemental inputs. Source references are descriptive; this service never fetches them. */
public final class SupplementalDecryptionKeyService {
    public record Scope(String targetEntityId, String metadataSha256, boolean testsStarted,
                        List<PublicKey> publishedEncryptionKeys) {
        public Scope { publishedEncryptionKeys=List.copyOf(publishedEncryptionKeys); }
    }
    public record Submission(String targetEntityId,String metadataSha256,String sourceUri,List<String> publicKeysSpkiBase64) {
        public Submission { publicKeysSpkiBase64=List.copyOf(publicKeysSpkiBase64); }
    }
    private final SqliteSupplementalDecryptionKeys repository;
    private final Function<String,Scope> scopes;
    private final Clock clock;
    public SupplementalDecryptionKeyService(SqliteSupplementalDecryptionKeys repository,Function<String,Scope> scopes,Clock clock) {
        this.repository=Objects.requireNonNull(repository);this.scopes=Objects.requireNonNull(scopes);this.clock=Objects.requireNonNull(clock);
    }
    /** Read-only: viewing the input does not lock a Run that has not started. */
    public Optional<SupplementalDecryptionKeys> inspect(String runId) {
        var scope=scopes.apply(runId);
        var input=repository.find(runId);input.ifPresent(value->requireScope(value,scope));return input;
    }
    /** Idempotent identical submission preserves the original timestamp and source. Replacement requires a new Run. */
    public SupplementalDecryptionKeys submit(String runId,Submission submission) {
        Objects.requireNonNull(submission);
        var scope=scopes.apply(runId);
        var input=new SupplementalDecryptionKeys(runId,submission.targetEntityId(),submission.metadataSha256(),
                submission.sourceUri(),submission.publicKeysSpkiBase64(),clock.instant());
        if(input.publicKeysSpkiBase64().isEmpty()) throw new IllegalArgumentException("Submit at least one public key");
        requireScope(input,scope);
        var existing=repository.find(runId);
        if(existing.isPresent()) return sameInputOrConflict(existing.orElseThrow(),input);
        if(scope.testsStarted()) {
            repository.freezeAbsent(absence(runId,scope));
            throw new IllegalStateException("Test inputs are fixed; use a new Run");
        }
        repository.insertIfAbsent(input);
        return sameInputOrConflict(repository.find(runId).orElseThrow(),input);
    }
    /** Invoked before tests start and before any dependent fixture is constructed, including on process restart. */
    public SupplementalDecryptionKeys freeze(String runId) {
        return repository.freezeAbsent(absence(runId,scopes.apply(runId)));
    }
    /** Published keys retain order; supplemental keys are appended without double-counting the same public key. */
    public List<PublicKey> effectiveKeys(String runId) {
        var scope=scopes.apply(runId);
        var input=repository.freezeAbsent(absence(runId,scope));
        var distinct=new LinkedHashMap<String,PublicKey>();
        for(var key:scope.publishedEncryptionKeys()) add(distinct,key);
        for(var key:input.publicKeys()) add(distinct,key);
        return List.copyOf(distinct.values());
    }
    private SupplementalDecryptionKeys absence(String run,Scope scope) {
        return SupplementalDecryptionKeys.absent(run,scope.targetEntityId(),scope.metadataSha256(),clock.instant());
    }
    private static void requireScope(SupplementalDecryptionKeys input,Scope scope) {
        if(!input.targetEntityId().equals(scope.targetEntityId()) || !input.metadataSha256().equals(scope.metadataSha256()))
            throw new IllegalArgumentException("Public-key input must match the Run target and metadata snapshot");
    }
    private static SupplementalDecryptionKeys sameInputOrConflict(SupplementalDecryptionKeys existing,SupplementalDecryptionKeys input) {
        if(!existing.targetEntityId().equals(input.targetEntityId()) || !existing.metadataSha256().equals(input.metadataSha256())
                || !Objects.equals(existing.sourceUri(),input.sourceUri()) || !existing.publicKeysSpkiBase64().equals(input.publicKeysSpkiBase64()))
            throw new IllegalStateException("Test inputs are fixed; use a new Run");
        return existing;
    }
    private static void add(Map<String,PublicKey> keys,PublicKey key) {
        if(!"RSA".equals(key.getAlgorithm())) throw new IllegalArgumentException("Expected an RSA encryption key");
        keys.putIfAbsent(Base64.getEncoder().encodeToString(key.getEncoded()),key);
    }
}
