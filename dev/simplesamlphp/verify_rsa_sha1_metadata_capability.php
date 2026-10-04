<?php

declare(strict_types=1);

if ($argc !== 4) {
    fwrite(STDERR, "usage: verify_rsa_sha1_metadata_capability.php metadata.xml trusted.crt wrong.crt\n");
    exit(64);
}

require '/var/simplesamlphp/lib/_autoload.php';

const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const DS = 'http://www.w3.org/2000/09/xmldsig#';

function verify_metadata(string $xml, string $certificate): bool
{
    try {
        $entity = \SimpleSAML\Metadata\SAMLParser::parseString($xml);
        return $entity->validateSignature([$certificate]);
    } catch (Throwable $error) {
        return false;
    }
}

function certificate_sha256(string $certificate): string
{
    $pem = file_get_contents($certificate);
    if ($pem === false || !preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $pem, $match)) {
        throw new RuntimeException('Certificate is unavailable');
    }
    $der = base64_decode(preg_replace('/\\s+/', '', $match[1]), true);
    if ($der === false) {
        throw new RuntimeException('Certificate is malformed');
    }
    return hash('sha256', $der);
}

$input = file_get_contents($argv[1]);
if ($input === false) {
    throw new RuntimeException('Metadata input is unavailable');
}
$document = new DOMDocument();
$document->preserveWhiteSpace = true;
if (!$document->loadXML($input, LIBXML_NONET | LIBXML_NOBLANKS)) {
    throw new RuntimeException('Metadata input is malformed');
}
$root = $document->documentElement;
if (!$root instanceof DOMElement || $root->namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:metadata'
    || $root->localName !== 'EntityDescriptor') {
    throw new RuntimeException('Expected one EntityDescriptor');
}
$xpath = new DOMXPath($document);
$xpath->registerNamespace('ds', DS);
$methods = $xpath->query('./ds:Signature/ds:SignedInfo/ds:SignatureMethod', $root);
if ($methods === false || $methods->length !== 1
    || !$methods->item(0) instanceof DOMElement
    || $methods->item(0)->getAttribute('Algorithm') !== RSA_SHA1) {
    throw new RuntimeException('Expected one RSA-SHA1 metadata signature');
}

$tampered = new DOMDocument();
$tampered->preserveWhiteSpace = true;
$tampered->loadXML($input, LIBXML_NONET | LIBXML_NOBLANKS);
$tampered->documentElement->setAttribute('entityID', $root->getAttribute('entityID') . '#tampered');
$tamperedXml = $tampered->saveXML();

$unsigned = new DOMDocument();
$unsigned->preserveWhiteSpace = true;
$unsigned->loadXML($input, LIBXML_NONET | LIBXML_NOBLANKS);
$unsignedXpath = new DOMXPath($unsigned);
$unsignedXpath->registerNamespace('ds', DS);
$signatures = $unsignedXpath->query('./ds:Signature', $unsigned->documentElement);
if ($signatures === false || $signatures->length !== 1) {
    throw new RuntimeException('Expected one metadata signature');
}
$signatures->item(0)->parentNode->removeChild($signatures->item(0));
$unsignedXml = $unsigned->saveXML();

$observation = [
    'schema' => 'samlscope-simplesamlphp-rsa-sha1-verification-v1',
    'inputSha256' => hash('sha256', $input),
    'targetEntityId' => $root->getAttribute('entityID'),
    'signatureAlgorithm' => RSA_SHA1,
    'trustedCertificateSha256' => certificate_sha256($argv[2]),
    'wrongCertificateSha256' => certificate_sha256($argv[3]),
    'tamperedInputBase64' => base64_encode((string) $tamperedXml),
    'tamperedInputSha256' => hash('sha256', (string) $tamperedXml),
    'unsignedInputBase64' => base64_encode((string) $unsignedXml),
    'unsignedInputSha256' => hash('sha256', (string) $unsignedXml),
    'positiveAccepted' => verify_metadata($input, $argv[2]),
    'tamperedAccepted' => verify_metadata((string) $tamperedXml, $argv[2]),
    'wrongKeyAccepted' => verify_metadata($input, $argv[3]),
    'unsignedAccepted' => verify_metadata((string) $unsignedXml, $argv[2]),
];

if (!$observation['positiveAccepted'] || $observation['tamperedAccepted']
    || $observation['wrongKeyAccepted'] || $observation['unsignedAccepted']
    || $observation['trustedCertificateSha256'] === $observation['wrongCertificateSha256']) {
    fwrite(STDERR, json_encode($observation, JSON_UNESCAPED_SLASHES) . "\n");
    exit(1);
}

echo json_encode($observation, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
