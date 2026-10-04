<?php
/** Public developer capability fixtures; no target settings, SAML sends, or private keys. */
require '/var/simplesamlphp/lib/_autoload.php';
$inputBytes = stream_get_contents(STDIN);
$input = json_decode($inputBytes, true, 512, JSON_THROW_ON_ERROR);
if (($input['schema'] ?? '') !== 'samlscope-simplesamlphp-self-contained-trust-input-v1'
    || count($input['records'] ?? []) !== 4
    || !in_array($input['selectedPath'] ?? '', ['stock-native-signature-encryption', 'developer-instrumented-additional-anchor'], true)) throw new RuntimeException('Incomplete public fixture set');
$instrumented = $input['selectedPath'] === 'developer-instrumented-additional-anchor';
$classes = [
    'native-idp.php' => \SimpleSAML\Module\saml\IdP\SAML2::class,
    'native-message.php' => \SimpleSAML\Module\saml\Message::class,
    'native-configuration.php' => \SimpleSAML\Configuration::class,
    'native-parser.php' => \SimpleSAML\Metadata\SAMLParser::class,
    'native-signed-helper.php' => \SAML2\SignedElementHelper::class,
    'native-xml-security-key.php' => \RobRichards\XMLSecLibs\XMLSecurityKey::class,
    'native-xml-security-dsig.php' => \RobRichards\XMLSecLibs\XMLSecurityDSig::class,
];
$selected = [];
foreach ($classes as $name => $class) {
    $file = (new ReflectionClass($class))->getFileName();
    if (!is_string($file) || !str_starts_with($file, '/var/simplesamlphp/')) throw new RuntimeException('Unexpected native class');
    $selected[$name] = ['class' => $class, 'file' => $file, 'sha256' => hash_file('sha256', $file)];
}
$records = [];
foreach ($input['records'] as $row) {
    $metadata = base64_decode($row['metadataBase64'], true);
    $request = base64_decode($row['requestBase64'], true);
    if ($metadata === false || $request === false || hash('sha256', $metadata) !== $row['fixtureSha256']
        || hash('sha256', $request) !== $row['requestSha256']) throw new RuntimeException('Public originals changed');
    $entities = \SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($metadata);
    $peer = $entities[$input['peerEntityId']] ?? null;
    if ($peer === null) throw new RuntimeException('Missing native peer');
    $sp = $peer->getMetadata20SP();
    if (!is_array($sp)) throw new RuntimeException('No native SP role');
    $configuration = \SimpleSAML\Configuration::loadFromArray($sp, 'developer-original-backed-role-fixture');
    $document = new DOMDocument();
    if (!$document->loadXML($request, LIBXML_NONET)) throw new RuntimeException('Invalid original request');
    $message = new \SAML2\AuthnRequest($document->documentElement);
    $valid = \SimpleSAML\Module\saml\Message::checkSign($configuration, $message);
    if (!$valid) throw new RuntimeException('Stock native signature control failed');
    $keys = $configuration->getPublicKeys('signing');
    if (count($keys) !== 1 || $keys[0]['type'] !== 'X509Certificate') throw new RuntimeException('Ambiguous operative signer');
    $certificate = base64_decode(preg_replace('/\s+/', '', $keys[0]['X509Certificate']), true);
    if ($certificate === false) throw new RuntimeException('Invalid public certificate');
    $fingerprint = hash('sha256', $certificate);
    // The explicitly instrumented developer mutant adds a separate anchor-input gate
    // after the actual installed signature verifier has accepted the same request.
    $requiredAnchor = static function (array $anchors) use ($valid, $fingerprint): bool {
        if (!$valid) throw new RuntimeException('The trust mutant requires a mathematically valid request');
        if (!in_array($fingerprint, $anchors, true)) throw new RuntimeException('ExternalTrustInputRequired:' . $fingerprint);
        return true;
    };
    $record = [
        'fixtureId' => $row['fixtureId'], 'fixtureSha256' => $row['fixtureSha256'],
        'requestReference' => $row['requestReference'], 'requestSha256' => $row['requestSha256'],
        'requestId' => $document->documentElement->getAttribute('ID'),
        'metadataSigningCertificateSha256' => $fingerprint,
        'stockNativeSignatureAccepted' => true, 'stockAdditionalTrustInputSupplied' => false,
        'selectedConsumer' => ['path' => $input['selectedPath'], 'accepted' => $valid,
            'additionalTrustInputRequired' => false, 'additionalTrustInputSupplied' => false],
    ];
    if ($instrumented) {
        $exception = null;
        try { $requiredAnchor([]); } catch (RuntimeException $e) { $exception = $e->getMessage(); }
        $withAnchor = $requiredAnchor([$fingerprint]);
        if ($exception !== 'ExternalTrustInputRequired:' . $fingerprint || !$withAnchor)
            throw new RuntimeException('Additional-anchor detector lacks differential control');
        $record['selectedConsumer'] = ['path' => $input['selectedPath'], 'accepted' => false,
            'additionalTrustInputRequired' => true, 'additionalTrustInputSupplied' => false,
            'exceptionClass' => RuntimeException::class, 'exceptionMessage' => $exception];
        $record['mutant'] = ['mathematicalSignatureAccepted' => true, 'additionalTrustInputRequired' => true,
            'additionalTrustInputSupplied' => false, 'rejected' => true,
            'exceptionClass' => RuntimeException::class, 'exceptionMessage' => $exception,
            'acceptedWithSamePublicAnchorSupplied' => $withAnchor, 'counterfactualCalibrationOnly' => true];
    }
    $records[] = $record;
}
$selectedAfter = [];
foreach ($classes as $name => $class) {
    $file = (new ReflectionClass($class))->getFileName();
    $selectedAfter[$name] = ['class' => $class, 'file' => $file, 'sha256' => hash_file('sha256', $file)];
}
if ($selected !== $selectedAfter) throw new RuntimeException('Native class source changed during selected operation');
echo json_encode([
    'schema' => 'samlscope-simplesamlphp-self-contained-trust-calibration-v1',
    'runId' => $input['runId'], 'peerEntityId' => $input['peerEntityId'],
    'targetMetadataSha256' => $input['targetMetadataSha256'], 'records' => $records,
    'selectedPath' => $input['selectedPath'], 'counterfactualCalibrationOnly' => $instrumented,
    'selectedNativeClasses' => $selected, 'selectedNativeClassesAfter' => $selectedAfter, 'sourceSha256' => hash_file('sha256', __FILE__),
    'inputSha256' => hash('sha256', $inputBytes),
    'productConfigurationWrites' => 0, 'protocolOperations' => 0, 'credentialPosts' => 0,
    'productRestarts' => 0, 'humanOperations' => 0, 'nativePrivateKeyUsed' => false,
    'mutantControlsAdopted' => false,
], JSON_THROW_ON_ERROR);
