<?php
declare(strict_types=1);

/** CONFIG instrumentation only. No SAML dispatch, login, or session operations. */
require '/var/simplesamlphp/lib/_autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, 64, JSON_THROW_ON_ERROR);
if (!function_exists('posix_geteuid') || posix_geteuid() !== 33) {
    throw new RuntimeException('Actual web-service UID required');
}
$run = $input['runId'] ?? '';
$peer = $input['peerEntityId'] ?? '';
$entity = $input['targetEntityId'] ?? '';
$digest = 'sha256:f0804b19a640f8dc668635a12630d2ac5dbb50193f04bed346a0e4afcc2ab9a8';
if (!preg_match('/^run_[0-9A-HJKMNP-TV-Z]{26}$/D', $run)
    || !preg_match('~^http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}$~D', $peer)
    || $entity !== 'http://localhost:18380/idp'
    || ($input['caseDigest'] ?? '') !== $digest
    || !preg_match('/^[0-9a-f]{64}$/D', $input['targetMetadataSha256'] ?? '')) {
    throw new RuntimeException('Unsupported Run/configuration scope');
}
$handler = \SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
$idp = $handler->getMetaDataConfig($entity, 'saml20-idp-hosted');
$restored = ($input['mode'] ?? '') === 'restored';
if ($restored) {
    if (array_key_exists($peer, $handler->getList('saml20-sp-remote'))) {
        throw new RuntimeException('Owned peer still configured after restoration');
    }
    $sp = \SimpleSAML\Configuration::loadFromArray(['entityid' => $peer]);
} else {
    $sp = $handler->getMetaDataConfig($peer, 'saml20-sp-remote');
}
$method = new ReflectionMethod(\SimpleSAML\Module\saml\Message::class, 'getDecryptionKeys');
$nativeFile = $method->getFileName();
$nativeSource = file_get_contents($nativeFile);
if (hash('sha256', $nativeSource) !== 'ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2') {
    throw new RuntimeException('Unsupported native Message source');
}

// The complete original source is fixed above. Remove only its optional new-key
// loading branch; the original shared-key and existing-key paths each yield one.
// This class is confined to this helper process, never the product HTTP process.
$startMarker = "        // load the new private key if it exists\n";
$endMarker = "        /**\n         * find the existing private key\n";
$start = strpos($nativeSource, $startMarker);
$end = strpos($nativeSource, $endMarker, $start === false ? 0 : $start);
if ($start === false || $end === false || $end <= $start
    || substr_count($nativeSource, $startMarker) !== 1
    || substr_count($nativeSource, $endMarker) !== 1
    || substr_count($nativeSource, 'namespace SimpleSAML\\Module\\saml;') !== 1) {
    throw new RuntimeException('Native capability-control patch is ambiguous');
}
$controlSource = substr($nativeSource, 0, $start) . substr($nativeSource, $end);
$controlSource = str_replace('namespace SimpleSAML\\Module\\saml;', 'namespace SAMLscopeDiagnostic;', $controlSource);
eval(substr($controlSource, strlen('<?php')));

$challenge = "SAMLscope-native-two-decryption-keys-v1\n" . $run . "\n" . $digest . "\n"
    . $entity . "\n" . $peer . "\n" . $input['targetMetadataSha256'] . "\n";
$observe = static function (array $keys) use ($challenge): array {
    $rows = [];
    foreach ($keys as $index => $key) {
        if (!$key instanceof \RobRichards\XMLSecLibs\XMLSecurityKey) {
            throw new RuntimeException('Unknown native private-key object');
        }
        $public = openssl_pkey_get_details($key->key);
        if ($public === false || $public['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new RuntimeException('Unsupported native key');
        }
        $der = base64_decode(preg_replace('/-----(?:BEGIN|END) PUBLIC KEY-----|\s/', '', $public['key']), true);
        if ($der === false || !openssl_sign($challenge, $signature, $key->key, OPENSSL_ALGO_SHA256)
            || openssl_verify($challenge, $signature, $public['key'], OPENSSL_ALGO_SHA256) !== 1) {
            throw new RuntimeException('Native loaded private key is unusable');
        }
        $rows[] = ['index' => $index, 'class' => get_class($key), 'spkiBase64' => base64_encode($der),
            'spkiSha256' => hash('sha256', $der), 'signatureBase64' => base64_encode($signature)];
    }
    return $rows;
};
$baselineObjects = \SimpleSAML\Module\saml\Message::getDecryptionKeys($sp, $idp);
$controlObjects = \SAMLscopeDiagnostic\Message::getDecryptionKeys($sp, $idp);
$baseline = $observe($baselineObjects);
$control = $observe($controlObjects);
$seal = static function (array $report, array $keys): void {
    $bytes = json_encode($report, JSON_THROW_ON_ERROR);
    $signatures = [];
    foreach ($keys as $index => $key) {
        $public = openssl_pkey_get_details($key->key)['key'];
        $der = base64_decode(preg_replace('/-----(?:BEGIN|END) PUBLIC KEY-----|\s/', '', $public), true);
        if ($der === false || !openssl_sign($bytes, $signature, $key->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Native observation signature unavailable');
        }
        $signatures[] = ['keyIndex' => $index, 'spkiSha256' => hash('sha256', $der),
            'signatureBase64' => base64_encode($signature)];
    }
    echo json_encode(['schema' => 'samlscope-native-key-observation-signed-v1',
        'payloadBase64' => base64_encode($bytes), 'payloadSha256' => hash('sha256', $bytes),
        'signatures' => $signatures], JSON_THROW_ON_ERROR);
};
if ($restored) {
    $seal(['schema' => 'samlscope-native-decryption-keys-restored-v1', 'runId' => $run,
        'caseDigest' => $digest, 'targetEntityId' => $entity, 'peerEntityId' => $peer,
        'effectiveUid' => posix_geteuid(), 'keys' => $baseline, 'challengeBase64' => base64_encode($challenge),
        'newPrivateKey' => $idp->getOptionalString('new_privatekey', null),
        'sourceSha256' => hash('sha256', $nativeSource), 'privateMaterialPersisted' => false], $baselineObjects);
    exit;
}
$decryptionControls = [];
foreach ($baselineObjects as $index => $private) {
    $publicDetails = openssl_pkey_get_details($private->key);
    $public = new \RobRichards\XMLSecLibs\XMLSecurityKey(
        \RobRichards\XMLSecLibs\XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'public']);
    $public->loadKey($publicDetails['key']);
    $name = new \SAML2\XML\saml\NameID();
    $name->setValue('urn:samlscope:configuration-key-control:' . hash('sha256', $challenge));
    $name->setFormat('urn:oasis:names:tc:SAML:2.0:nameid-format:transient');
    $request = new \SAML2\LogoutRequest();
    $issuer = new \SAML2\XML\saml\Issuer();
    $issuer->setValue($peer);
    $request->setIssuer($issuer);
    $request->setNameId($name);
    $request->encryptNameId($public);
    $xml = $request->toUnsignedXML()->ownerDocument->saveXML();
    $attempts = [];
    foreach (['baseline' => $baselineObjects, 'capability-removed' => $controlObjects] as $engine => $keys) {
        foreach ($keys as $keyIndex => $key) {
            $document = \SAML2\DOMDocumentFactory::fromString($xml);
            $parsed = new \SAML2\LogoutRequest($document->documentElement);
            try {
                $parsed->decryptNameId($key);
                $actual = $parsed->getNameId();
                $attempts[] = ['engine' => $engine, 'keyIndex' => $keyIndex, 'decrypted' => true,
                    'nameId' => $actual->getValue(), 'format' => $actual->getFormat()];
            } catch (Throwable $failure) {
                $attempts[] = ['engine' => $engine, 'keyIndex' => $keyIndex, 'decrypted' => false,
                    'exceptionClass' => get_class($failure)];
            }
        }
    }
    $decryptionControls[] = ['encryptionKeyIndex' => $index, 'encryptedRequestBase64' => base64_encode($xml),
        'encryptedRequestSha256' => hash('sha256', $xml), 'attempts' => $attempts];
}
$classes = [];
foreach ([\SimpleSAML\Module\saml\Message::class, \SimpleSAML\Configuration::class,
    \SimpleSAML\Utils\Crypto::class, \SimpleSAML\Metadata\MetaDataStorageHandler::class,
    \RobRichards\XMLSecLibs\XMLSecurityKey::class, \SAML2\LogoutRequest::class,
    \SAML2\DOMDocumentFactory::class, \SAML2\Utils::class,
    \SAML2\XML\saml\NameID::class, \RobRichards\XMLSecLibs\XMLSecEnc::class] as $class) {
    $reflection = new ReflectionClass($class);
    $file = $reflection->getFileName();
    $classes[] = ['class' => $class, 'file' => $file, 'sha256' => hash_file('sha256', $file)];
}
$dependencies = [];
foreach (get_included_files() as $file) {
    if (preg_match('~^/var/simplesamlphp/(?:src|vendor|modules|lib)/~D', $file)) {
        $dependencies[] = ['file' => $file, 'sha256' => hash_file('sha256', $file), 'bytes' => filesize($file)];
    }
}
usort($dependencies, static fn(array $a, array $b): int => strcmp($a['file'], $b['file']));
$settings = [];
foreach (['hosted' => '/var/simplesamlphp/metadata/saml20-idp-hosted.php',
    'remote' => '/var/simplesamlphp/metadata/saml20-sp-remote.php',
    'override' => '/var/simplesamlphp/config/config-override.php'] as $label => $file) {
    $settings[$label] = hash_file('sha256', $file);
}
$seal(['schema' => 'samlscope-native-multiple-decryption-keys-observation-v1',
    'runId' => $run, 'caseId' => 'IIP-IDP19-b-idp-01', 'caseDigest' => $digest,
    'targetEntityId' => $entity, 'peerEntityId' => $peer,
    'targetMetadataSha256' => $input['targetMetadataSha256'],
    'challengeBase64' => base64_encode($challenge), 'challengeSha256' => hash('sha256', $challenge),
    'nativeMethod' => ['class' => $method->getDeclaringClass()->getName(), 'method' => $method->getName(),
        'file' => $nativeFile, 'sha256' => hash('sha256', $nativeSource),
        'startLine' => $method->getStartLine(), 'endLine' => $method->getEndLine()],
    'control' => ['namespace' => 'SAMLscopeDiagnostic', 'sourceSha256' => hash('sha256', $controlSource),
        'removedStartOffset' => $start, 'removedEndOffset' => $end, 'keys' => $control],
    'baselineKeys' => $baseline, 'decryptionControls' => $decryptionControls,
    'keyConfiguration' => ['newPrivateKey' => $idp->getOptionalString('new_privatekey', null),
        'newCertificate' => $idp->getOptionalString('new_certificate', null),
        'existingPrivateKey' => $idp->getOptionalString('privatekey', null),
        'sharedKeySelected' => $sp->getOptionalString('sharedkey', null) !== null],
    'loadedClasses' => $classes, 'dependencies' => $dependencies,
    'settingsSha256' => $settings, 'effectiveUid' => posix_geteuid(),
    'phpVersion' => PHP_VERSION, 'opensslVersion' => OPENSSL_VERSION_TEXT,
    'privateMaterialPersisted' => false], $baselineObjects);
