package com.samlscope.saml.crypto;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import com.samlscope.saml.normal.SamlException;
import org.w3c.dom.Element;
import java.util.List;

public final class XmlSigner {
    static { Init.init(); }

    public void sign(Element target, PlanCredentials credentials, Element insertBefore) {
        sign(target, credentials, insertBefore, SignatureOptions.standard());
    }

    public void sign(
            Element target,
            PlanCredentials credentials,
            Element insertBefore,
            SignatureOptions options) {
        try {
            var document = target.getOwnerDocument();
            var id = target.getAttribute("ID");
            if (id.isBlank()) throw new SamlException("Signed element has no ID");
            target.setIdAttribute("ID", true);
            var signature = new XMLSignature(
                    document,
                    "",
                    signatureAlgorithm(credentials),
                    Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            if (insertBefore == null) target.appendChild(signature.getElement());
            else target.insertBefore(signature.getElement(), insertBefore);
            var transforms = new Transforms(document);
            for (var transform : options.transforms()) {
                if (transform.xpath() == null) {
                    transforms.addTransform(transform.algorithm());
                } else {
                    var xpath = document.createElementNS(
                            "http://www.w3.org/2000/09/xmldsig#", "ds:XPath");
                    xpath.setAttributeNS(
                            "http://www.w3.org/2000/xmlns/", "xmlns:md",
                            "urn:oasis:names:tc:SAML:2.0:metadata");
                    xpath.setAttributeNS(
                            "http://www.w3.org/2000/xmlns/", "xmlns:samlp",
                            "urn:oasis:names:tc:SAML:2.0:protocol");
                    xpath.setAttributeNS(
                            "http://www.w3.org/2000/xmlns/", "xmlns:saml",
                            "urn:oasis:names:tc:SAML:2.0:assertion");
                    xpath.setTextContent(transform.xpath());
                    transforms.addTransform(transform.algorithm(), xpath);
                }
            }
            signature.addDocument("#" + id, transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
            if (options.includeKeyInfo()) signature.addKeyInfo(credentials.certificate());
            signature.sign(credentials.privateKey());
        } catch (SamlException e) {
            throw e;
        } catch (Exception e) {
            throw new SamlException("Could not sign XML", e);
        }
    }

    private static String signatureAlgorithm(PlanCredentials credentials) {
        return switch (credentials.privateKey().getAlgorithm()) {
            case "RSA" -> XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
            case "EC" -> XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
            default -> throw new SamlException("Unsupported XML signing key algorithm");
        };
    }

    public record TransformSpec(String algorithm, String xpath) {
        public TransformSpec {
            if (algorithm == null || algorithm.isBlank()) {
                throw new IllegalArgumentException("transform algorithm is required");
            }
            if (xpath != null && xpath.isBlank()) throw new IllegalArgumentException("xpath must not be blank");
        }

        public static TransformSpec algorithm(String algorithm) { return new TransformSpec(algorithm, null); }
        public static TransformSpec xpath(String expression) {
            return new TransformSpec(Transforms.TRANSFORM_XPATH, expression);
        }
    }

    public record SignatureOptions(boolean includeKeyInfo, List<TransformSpec> transforms) {
        public SignatureOptions {
            transforms = List.copyOf(transforms);
            if (transforms.isEmpty()) throw new IllegalArgumentException("at least one transform is required");
        }

        public static SignatureOptions standard() {
            return new SignatureOptions(true, List.of(
                    TransformSpec.algorithm(Transforms.TRANSFORM_ENVELOPED_SIGNATURE),
                    TransformSpec.algorithm(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)));
        }
    }
}
