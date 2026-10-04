<?php

declare(strict_types=1);

/*
 * Reference-only adapter for SimpleSAMLphp's native metadata signature verifier.
 *
 * The adapter enters through Metadata\Sources\MDQ::getMetaData.  MDQ fetches the
 * original Suite fixture, SAMLParser parses it, and validateSignature checks the
 * explicitly configured out-of-band certificate.  The exact result is posted by
 * this product process to the Suite Recorder.  It never assigns a SAMLscope verdict.
 */

require '/var/simplesamlphp/lib/_autoload.php';

use SimpleSAML\Configuration;
use SimpleSAML\Metadata\MetaDataStorageSource;

const PARSER_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php';
const MDQ_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Metadata/Sources/MDQ.php';
const METALOADER_SOURCE = '/var/simplesamlphp/modules/metarefresh/src/MetaLoader.php';
const CONFIGURATION_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Configuration.php';

function abortAdapter(string $message, int $code = 2): never
{
    fwrite(STDERR, $message . "\n");
    exit($code);
}

function pemDer(string $path): string
{
    $pem = file_get_contents($path);
    if (!is_string($pem)) {
        abortAdapter('Trust anchor is unreadable');
    }
    if (!preg_match('/-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----/s', $pem, $match)) {
        abortAdapter('Trust anchor is not a PEM certificate');
    }
    $der = base64_decode(preg_replace('/\s+/', '', $match[1]), true);
    if (!is_string($der) || $der === '') {
        abortAdapter('Trust anchor DER is invalid');
    }
    return $der;
}

function postBytes(string $url, string $raw, string $contentType): string
{
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "Content-Type: " . $contentType . "\r\nConnection: close\r\n",
        'content' => $raw,
        'ignore_errors' => true,
        'timeout' => 30,
    ]]);
    $response = file_get_contents($url, false, $context);
    $status = $http_response_header[0] ?? '';
    if ($response === false || !preg_match('/\s204(?:\s|$)/', $status)) {
        abortAdapter('Suite Recorder did not return HTTP 204', 4);
    }
    fwrite(STDOUT, $raw);
    return $raw;
}

function postOriginal(string $url, array $record): string
{
    return postBytes($url, json_encode(
        $record,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
    ) . "\n", 'application/json');
}

function recordFile(array $args): never
{
    if (count($args) !== 3) {
        abortAdapter('record-file requires path and recorder');
    }
    [, $path, $recorder] = $args;
    $raw = file_get_contents($path);
    if (!is_string($raw)) abortAdapter('Original file is unreadable');
    postBytes($recorder, $raw, 'application/octet-stream');
    exit(0);
}

function recordEffectiveConfiguration(array $args): never
{
    if (count($args) !== 2) {
        abortAdapter('record-effective requires recorder');
    }
    [, $recorder] = $args;
    $raw = json_encode(Configuration::getInstance()->getArray('metadata.sources'),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    postBytes($recorder, $raw, 'application/json');
    exit(0);
}

function configurationArtifact(array $args): never
{
    if (count($args) !== 6) {
        abortAdapter('configuration requires run, target, anchor, configuration, recorder');
    }
    [, $run, $target, $anchorPath, $configurationPath, $recorder] = $args;
    $der = pemDer($anchorPath);
    $configuration = file_get_contents($configurationPath);
    if (!is_string($configuration)) {
        abortAdapter('Product configuration is unreadable');
    }
    postOriginal($recorder, [
        'artifact' => 'metadata-signature-trust-configuration',
        'runId' => $run,
        'targetEntityId' => $target,
        'signatureVerification' => 'enabled',
        'nativeValidationConfiguration' => [
            'sourceType' => 'mdq',
            'option' => 'validateCertificate',
            'certificateLocation' => basename($anchorPath),
        ],
        'trustAnchorCertificates' => [base64_encode($der)],
        'configurationSha256' => hash('sha256', $configuration),
    ]);
    exit(0);
}

function restorationArtifact(array $args): never
{
    if (count($args) !== 6) {
        abortAdapter('restoration requires run, target, configuration, expected hash, recorder');
    }
    [, $run, $target, $configurationPath, $expectedHash, $recorder] = $args;
    $configuration = file_get_contents($configurationPath);
    if (!is_string($configuration) || hash('sha256', $configuration) !== $expectedHash) {
        abortAdapter('Product configuration does not match the captured original');
    }
    postOriginal($recorder, [
        'artifact' => 'metadata-signature-configuration-restored',
        'runId' => $run,
        'targetEntityId' => $target,
        'restored' => true,
        'trustAnchorCertificates' => [],
        'configurationSha256' => $expectedHash,
    ]);
    exit(0);
}

function validateMetadata(array $args): never
{
    if (count($args) !== 15) {
        abortAdapter('validate requires run, campaign, target, variant, entity, anchor, server, fixture file, fixture hash, recorder, cache dir, configuration reference, effective reference, configuration file');
    }
    [, $run, $campaign, $target, $variant, $entity, $anchorPath, $server,
        $fixturePath, $expectedFixtureHash, $recorder, $cacheDir, $configurationReference,
        $effectiveConfigurationReference, $configurationPath] = $args;
    $der = pemDer($anchorPath);
    $configurationRaw = file_get_contents($configurationPath);
    if (!is_string($configurationRaw)) {
        abortAdapter('Product configuration is unreadable');
    }
    $effectiveSources = Configuration::getInstance()->getArray('metadata.sources');
    $effectiveMatches = array_values(array_filter($effectiveSources, static fn ($source): bool =>
        is_array($source)
        && ($source['type'] ?? null) === 'mdq'
        && ($source['server'] ?? null) === $server
        && ($source['cachelength'] ?? null) === 0
        && ($source['validateCertificate'] ?? null) === [basename($anchorPath)]
    ));
    if (count($effectiveMatches) !== 1) {
        abortAdapter('Effective product MDQ signature configuration is not exact');
    }
    if (file_exists($cacheDir)) {
        abortAdapter('Native MDQ cache directory already exists');
    }
    if (!mkdir($cacheDir, 0700, true)) {
        abortAdapter('Cannot create isolated native MDQ cache');
    }

    $accepted = false;
    $signatureRejected = false;
    $metadataEntity = $entity;
    $exception = null;
    try {
        $source = MetaDataStorageSource::getSource([
            'type' => 'mdq',
            'server' => $server,
            'cachelength' => 0,
            'cachedir' => $cacheDir,
            'validateCertificate' => [basename($anchorPath)],
        ]);
        $metadata = $source->getMetaData($entity, 'saml20-sp-remote');
        if (!is_array($metadata) || ($metadata['entityid'] ?? null) !== $entity) {
            throw new RuntimeException('Native MDQ returned no matching SP metadata');
        }
        $metadataEntity = (string) $metadata['entityid'];
        $accepted = true;
    } catch (Throwable $error) {
        $exception = ['class' => get_class($error), 'message' => $error->getMessage()];
        $signatureRejected = get_class($error) === 'Exception'
            && str_starts_with(
                $error->getMessage(),
                'SimpleSAML\\Metadata\\Sources\\MDQ: error, could not verify signature for entity: ',
            )
            && str_contains($error->getMessage(), $entity);
    }

    $fixture = file_get_contents($fixturePath);
    if (!is_string($fixture) || hash('sha256', $fixture) !== $expectedFixtureHash) {
        abortAdapter('Native MDQ fetched bytes differ from the Suite fixture');
    }
    $record = [
        'schema' => 'samlscope-simplesamlphp-metadata-signature-validation-v1',
        'artifact' => 'metadata-signature-native-validation',
        'runId' => $run,
        'campaignId' => $campaign,
        'targetEntityId' => $target,
        'variant' => $variant,
        'product' => 'simplesamlphp',
        'productVersion' => Configuration::VERSION,
        'fixtureSha256' => hash('sha256', $fixture),
        'metadataEntityId' => $metadataEntity,
        'entryPoint' => 'SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData',
        'verifier' => 'SimpleSAML\\Metadata\\SAMLParser::validateSignature',
        'genericParserOnly' => false,
        'validationCallCount' => 1,
        'configurationReference' => $configurationReference,
        'effectiveConfigurationReference' => $effectiveConfigurationReference,
        'configurationSha256' => hash('sha256', $configurationRaw),
        'certificateLocation' => basename($anchorPath),
        'trustAnchorCertificateSha256' => hash('sha256', $der),
        'parserAccepted' => $accepted || $signatureRejected,
        'signatureVerified' => $accepted,
        'outcome' => $accepted ? 'accepted' : ($signatureRejected ? 'rejected' : 'error'),
        'exception' => $exception,
        'callPath' => [
            'SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData',
            'SimpleSAML\\Metadata\\SAMLParser::parseString',
            'SimpleSAML\\Metadata\\SAMLParser::validateSignature',
        ],
        'sourceSha256' => [
            'samlParser' => hash_file('sha256', PARSER_SOURCE),
            'mdq' => hash_file('sha256', MDQ_SOURCE),
            'metaLoader' => hash_file('sha256', METALOADER_SOURCE),
            'configuration' => hash_file('sha256', CONFIGURATION_SOURCE),
            'adapter' => hash_file('sha256', __FILE__),
        ],
    ];
    postOriginal($recorder, $record);

    // The cache is evidence-neutral working state and must not survive the operation.
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($cacheDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );
    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($cacheDir);
    if ($accepted) exit(0);
    if ($signatureRejected) exit(3);
    exit(5);
}

$mode = $argv[1] ?? '';
$args = array_values(array_slice($argv, 1));
match ($mode) {
    'record-file' => recordFile($args),
    'record-effective' => recordEffectiveConfiguration($args),
    'configuration' => configurationArtifact($args),
    'restoration' => restorationArtifact($args),
    'validate' => validateMetadata($args),
    default => abortAdapter('Expected configuration, restoration, or validate mode'),
};
