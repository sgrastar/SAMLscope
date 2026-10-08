package com.samlscope.core.transcript;

public interface TranscriptContentReader {
    byte[] readDecodedSaml(TranscriptEntry entry);

    /** Original recorded HTTP body, after the Recorder's mandatory credential redaction. */
    default byte[] readBody(TranscriptEntry entry) {
        throw new UnsupportedOperationException("Original Transcript body reader is unavailable");
    }
}
