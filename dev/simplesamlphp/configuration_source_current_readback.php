<?php
declare(strict_types=1);

/** Read only native configuration identity. No login, SAML dispatch, or settings update. */
require '/var/simplesamlphp/lib/_autoload.php';
$raw = stream_get_contents(STDIN);
$input = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
$required = ['sourceRunId', 'recipientRunId', 'caseDigest', 'targetEntityId', 'sourcePeerEntityId',
    'sourceTargetMetadataSha256', 'recipientTargetMetadataSha256', 'targetIdentitySha256',
    'sourceManifestSha256', 'bindingFenceSha256'];
if (array_diff(array_keys($input), $required) || array_diff($required, array_keys($input))
    || posix_geteuid() !== 33
    || $input['sourceRunId'] === $input['recipientRunId']
    || !preg_match('/^run_[0-9A-HJKMNP-TV-Z]{26}$/D', $input['sourceRunId'])
    || !preg_match('/^run_[0-9A-HJKMNP-TV-Z]{26}$/D', $input['recipientRunId'])
    || $input['caseDigest'] !== 'sha256:f0804b19a640f8dc668635a12630d2ac5dbb50193f04bed346a0e4afcc2ab9a8'
    || $input['targetEntityId'] !== 'http://localhost:18380/idp'
    || !preg_match('~^http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}$~D', $input['sourcePeerEntityId'])) {
    throw new RuntimeException('Unsupported independent configuration source binding');
}
foreach (['sourceTargetMetadataSha256', 'recipientTargetMetadataSha256', 'targetIdentitySha256',
    'sourceManifestSha256', 'bindingFenceSha256'] as $field) {
    if (!preg_match('/^[0-9a-f]{64}$/D', $input[$field])) {
        throw new RuntimeException('Invalid source binding digest');
    }
}
$started = microtime(true);
$metadataSources = \SimpleSAML\Configuration::getInstance()->getArray('metadata.sources', [['type' => 'flatfile']]);
if ($metadataSources !== [['type' => 'flatfile']]) {
    throw new RuntimeException('The restored stock native metadata source is required');
}
$handler = \SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
if (array_key_exists($input['sourcePeerEntityId'], $handler->getList('saml20-sp-remote'))) {
    throw new RuntimeException('Source-owned peer was not restored');
}
$hosted = $handler->getMetaDataConfig($input['targetEntityId'], 'saml20-idp-hosted');
if ($hosted->getOptionalString('new_privatekey', null) !== null
    || $hosted->getOptionalString('new_certificate', null) !== null) {
    throw new RuntimeException('Temporary decryption key configuration remains');
}
$peer = \SimpleSAML\Configuration::loadFromArray(['entityid' => $input['sourcePeerEntityId']]);
$keys = \SimpleSAML\Module\saml\Message::getDecryptionKeys($peer, $hosted);
if (count($keys) !== 1 || !$keys[0] instanceof \RobRichards\XMLSecLibs\XMLSecurityKey) {
    throw new RuntimeException('Unrecognized restored native key state');
}
$nativeCertificate = (new \SimpleSAML\Utils\Crypto())->loadPublicKey($hosted, true);
$certificateDer = base64_decode($nativeCertificate['certData'], true);
if ($certificateDer === false || openssl_x509_read($nativeCertificate['PEM']) === false) {
    throw new RuntimeException('Native restored public certificate unavailable');
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
$settings = [];
foreach (['hosted' => '/var/simplesamlphp/metadata/saml20-idp-hosted.php',
    'remote' => '/var/simplesamlphp/metadata/saml20-sp-remote.php',
    'override' => '/var/simplesamlphp/config/config-override.php'] as $name => $file) {
    if (is_link($file) || !is_file($file)) {
        throw new RuntimeException('Unsafe configuration file');
    }
    $settings[$name] = hash_file('sha256', $file);
}
$dependencies = [];
foreach (get_included_files() as $file) {
    if (preg_match('~^/var/simplesamlphp/(?:src|vendor|modules|lib)/~D', $file)) {
        $dependencies[] = ['file' => $file, 'sha256' => hash_file('sha256', $file), 'bytes' => filesize($file)];
    }
}
usort($dependencies, static fn(array $a, array $b): int => strcmp($a['file'], $b['file']));
$public = openssl_pkey_get_details($keys[0]->key);
if ($public === false || $public['type'] !== OPENSSL_KEYTYPE_RSA) {
    throw new RuntimeException('Unrecognized native key');
}
$der = base64_decode(preg_replace('/-----(?:BEGIN|END) PUBLIC KEY-----|\s/', '', $public['key']), true);
if ($der === false) {
    throw new RuntimeException('Public key serialization failed');
}
$report = ['schema' => 'samlscope-native-configuration-source-current-v1', 'input' => $input,
    'inputSha256' => hash('sha256', $raw), 'effectiveUid' => posix_geteuid(),
    'nativeStartedAt' => $started, 'nativeFinishedAt' => microtime(true),
    'settingsSha256' => $settings, 'loadedClasses' => $classes, 'dependencies' => $dependencies,
    'metadataSources' => $metadataSources, 'phpVersion' => PHP_VERSION, 'opensslVersion' => OPENSSL_VERSION_TEXT,
    'baselineKeys' => [['index' => 0, 'spkiSha256' => hash('sha256', $der), 'spkiBase64' => base64_encode($der)]],
    'certificateDerBase64' => base64_encode($certificateDer), 'certificateSha256' => hash('sha256', $certificateDer),
    'sourcePeerPresent' => false, 'newPrivateKey' => null, 'newCertificate' => null,
    'nativeMethod' => \SimpleSAML\Module\saml\Message::class . '::getDecryptionKeys',
    'privateMaterialPersisted' => false];
$bytes = json_encode($report, JSON_THROW_ON_ERROR);
if (!openssl_sign($bytes, $signature, $keys[0]->key, OPENSSL_ALGO_SHA256)) {
    throw new RuntimeException('Native public observation signature unavailable');
}
echo json_encode(['schema' => 'samlscope-native-key-observation-signed-v1',
    'payloadBase64' => base64_encode($bytes), 'payloadSha256' => hash('sha256', $bytes),
    'signatures' => [['keyIndex' => 0, 'spkiSha256' => hash('sha256', $der),
        'signatureBase64' => base64_encode($signature)]]], JSON_THROW_ON_ERROR);
