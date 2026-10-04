package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.util.*;
import java.util.function.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.metadata.MetadataService;

/** Producer capability evidence; native metadata consumption itself is not being judged here. */
final class MetadataEncryptionAlgorithmEvidence {
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",S="urn:oasis:names:tc:SAML:2.0:assertion",X="http://www.w3.org/2001/04/xmlenc#";
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    MetadataEncryptionAlgorithmEvidence(TranscriptContentReader content,Function<String,byte[]> metadata,
            BiFunction<String,String,Optional<PlanCredentials>> keys) {
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    List<EncryptionAlgorithmObservation.Observation> observe(CaseContext context) {
        var observations=new ArrayList<EncryptionAlgorithmObservation.Observation>();
        try {
            var variants=Arrays.stream(MetadataService.Variant.values()).map(MetadataService.Variant::id)
                    .filter(v->v.equals("control") || v.startsWith("algorithm-")).toList();
            var collected=MetadataAlgorithmEvidence.collect(variants,context,content,metadata.apply(context.runId()));
            if(!collected.issues().isEmpty())return List.of();
            for(var e:collected.exchanges()) {
                try {
                    var key=keys.apply(context.runId(),e.variant()).orElseThrow();
                    MetadataEncryptionProof.descriptor(children(e.metadata(),MD,"SPSSODescriptor").getFirst(),key);
                    var wrappers=children(e.response(),S,"EncryptedAssertion");
                    if(wrappers.isEmpty() || !children(e.response(),S,"Assertion").isEmpty())continue;
                    var batch=new ArrayList<EncryptionAlgorithmObservation.Observation>();
                    for(var wrapper:wrappers) {
                        // A single original data/key structure avoids selecting a decoy algorithm header.
                        if(children(wrapper,X,"EncryptedData").size()!=1 || wrapper.getElementsByTagNameNS(X,"EncryptedKey").getLength()!=1)
                            throw new IllegalArgumentException("Ambiguous encrypted assertion");
                        var data=children(wrapper,X,"EncryptedData").getFirst();
                        var transport=(org.w3c.dom.Element)wrapper.getElementsByTagNameNS(X,"EncryptedKey").item(0);
                        if(children(data,X,"EncryptionMethod").size()!=1 || children(transport,X,"EncryptionMethod").size()!=1)
                            throw new IllegalArgumentException("Ambiguous encryption method");
                        MetadataEncryptionProof.decrypt(e,wrapper,key);
                        batch.add(EncryptionAlgorithmObservation.inspect(e.evidence().get(2),e.evidence().get(3),wrapper,true));
                    }
                    observations.addAll(batch);
                } catch(Exception unavailable) { /* Missing keys or a failed proof are not a target violation. */ }
            }
        } catch(RuntimeException unavailable) { return List.of(); }
        return List.copyOf(observations);
    }
}
