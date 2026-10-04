package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.w3c.dom.Element;

/** Read-only native default-policy and actual algorithm-consumer evidence; never sends requests. */
public interface DefaultAlgorithmNativeAdapter {
    String adapter();
    /** No probes may be offered until this native, original-backed qualification succeeds. */
    default Optional<Preparation> prepare(CaseContext context,Path folder,JsonNode manifest,
            byte[] fixedTargetMetadata,byte[] registeredSuiteMetadata) throws Exception {
        return Optional.empty();
    }
    record Preparation(String policyId,boolean keyTransportConsumerAvailable,List<EvidenceRef> evidence) {
        public Preparation { evidence=List.copyOf(evidence); }
    }
    Session open(CaseContext context,Path folder,JsonNode manifest,byte[] fixedTargetMetadata,
            byte[] registeredSuiteMetadata) throws Exception;
    enum Decision { CONSUMED_SUCCESS,ALGORITHM_REJECTION,INVALID_SIGNATURE_REJECTION,UNPROVEN }
    /**
     * A native adapter may bind an early decoder rejection to the exact successful
     * control input. Both references must be verified Recorder originals; this
     * is not a receipt declaration that arbitrary consumers are equivalent.
     */
    record IngressRejectionProof(String acceptedControlConsumerId,EvidenceRef positiveControlInput,
            EvidenceRef nativeDecoderOriginal) {
        public IngressRejectionProof {
            if(acceptedControlConsumerId==null||acceptedControlConsumerId.isBlank()
                    ||positiveControlInput==null||nativeDecoderOriginal==null
                    ||!"transcript".equals(positiveControlInput.kind())
                    ||!"transcript".equals(nativeDecoderOriginal.kind())
                    ||positiveControlInput.equals(nativeDecoderOriginal))
                throw new IllegalArgumentException("Distinct native decoder and positive-control originals required");
        }
    }
    record Use(String policyId,String consumerId,Decision decision,List<EvidenceRef> evidence,
            IngressRejectionProof ingressRejectionProof) {
        public Use { evidence=List.copyOf(evidence); }
        public Use(String policyId,String consumerId,Decision decision,List<EvidenceRef> evidence) {
            this(policyId,consumerId,decision,evidence,null);
        }
    }
    interface Session {
        /**
         * Verify unchanged selected default policy/config/runtime, exact native operation and
         * explicit cause from original bytes. A parser/API, HTTP error, missing response, or
         * declared boolean cannot prove consumption or algorithm rejection. Encrypted-ID
         * acceptance requires native decrypted identity/session equality, not ignored ciphertext.
         */
        Use validate(JsonNode observation,String fixture,Element input,byte[] inputBytes,
                Element responseOrNull,Element authenticatedNameId,List<String> sessionIndexes)
                throws Exception;
    }
}
