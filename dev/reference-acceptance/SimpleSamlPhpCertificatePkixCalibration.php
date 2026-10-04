<?php
/* Public-only developer mutant calibration. Never a stock-product finding. */
declare(strict_types=1);
require '/var/simplesamlphp/lib/_autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$variant = $input['variant'] ?? '';
if (($input['schema'] ?? '') !== 'samlscope-ssp-openssl-calibration-input-v1' ||
    !in_array($variant, ['certificate-revoked', 'certificate-revocation-unreachable'], true)) {
    throw new RuntimeException('Unsupported calibration input');
}
$request = base64_decode($input['requestBase64'], true);
$fixture = base64_decode($input['fixtureBase64'], true);
if ($request === false || $fixture === false ||
    hash('sha256', $request) !== $input['requestSha256'] ||
    hash('sha256', $fixture) !== $input['fixtureSha256']) {
    throw new RuntimeException('Public input hash differs');
}
$dom = \SAML2\DOMDocumentFactory::fromString($request);
$q = $dom->documentElement;
if ($q->namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:protocol' ||
    $q->localName !== 'AuthnRequest' || $q->getAttribute('ID') !== $input['requestId']) {
    throw new RuntimeException('AuthnRequest binding differs');
}
$md = new DOMDocument();
if (!$md->loadXML($fixture, LIBXML_NONET)) { throw new RuntimeException('Invalid metadata'); }
$xp = new DOMXPath($md);
$xp->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
$xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
$xp->registerNamespace('rev', 'urn:samlscope:test:certificate-revocation');
$extract = static function(string $path) use ($xp): string {
    $nodes = $xp->query($path);
    if ($nodes->length !== 1) { throw new RuntimeException('Non-unique public material'); }
    $bytes = base64_decode(preg_replace('/\s+/', '', $nodes->item(0)->textContent), true);
    if ($bytes === false) { throw new RuntimeException('Invalid public DER'); }
    return $bytes;
};
$leaf = $extract('/md:EntityDescriptor/md:SPSSODescriptor/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate');
$issuer = $extract('/md:EntityDescriptor/md:Extensions/rev:RevocationOriginals/rev:IssuerCertificate');
$crl = $variant === 'certificate-revoked' ?
    $extract('/md:EntityDescriptor/md:Extensions/rev:RevocationOriginals/rev:CRL') : null;
$entity = $md->documentElement->getAttribute('entityID');
$issuers = $q->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer');
if ($issuers->length !== 1 || $issuers->item(0)->parentNode !== $q ||
    $issuers->item(0)->textContent !== $entity) {
    throw new RuntimeException('Request is not from the accepted metadata entity');
}
$entities = \SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($fixture);
if (!isset($entities[$entity])) { throw new RuntimeException('Native metadata entity absent'); }
$nativeMetadata = $entities[$entity]->getMetadata20SP();
$native = \SimpleSAML\Configuration::loadFromArray($nativeMetadata);
$signatureValid = \SimpleSAML\Module\saml\Message::checkSign($native, new \SAML2\AuthnRequest($q));
if ($signatureValid !== true) { throw new RuntimeException('Original request signature invalid'); }
$signatureVerifiedAt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z');
$openssl = '/usr/bin/openssl';
if (!is_executable($openssl)) { throw new RuntimeException('Native OpenSSL CLI unavailable'); }
$folder = sys_get_temp_dir() . '/ssp-certificate-calibration-' . bin2hex(random_bytes(12));
if (!mkdir($folder, 0700)) { throw new RuntimeException('Cannot allocate public calibration folder'); }
$pem = static fn(string $type, string $der): string => "-----BEGIN $type-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $type-----\n";
$run = static function(array $command): array {
    $started = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z');
    $proc = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) { throw new RuntimeException('Cannot execute native OpenSSL'); }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $stdout = ''; $stderr = ''; $deadline = microtime(true) + 12; $timedOut = false;
    do {
        $stdout .= stream_get_contents($pipes[1]); $stderr .= stream_get_contents($pipes[2]);
        $state = proc_get_status($proc);
        if (!$state['running']) { break; }
        if (microtime(true) >= $deadline || strlen($stdout) + strlen($stderr) > 1048576) {
            $timedOut = true; proc_terminate($proc); usleep(200000);
            if (proc_get_status($proc)['running']) { proc_terminate($proc, 9); }
            break;
        }
        usleep(10000);
    } while (true);
    $stdout .= stream_get_contents($pipes[1]); $stderr .= stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]); $closed = proc_close($proc);
    $exit = $timedOut ? 124 : ($state['exitcode'] >= 0 ? $state['exitcode'] : $closed);
    return ['command' => $command, 'startedAt' => $started,
        'completedAt' => (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.u\Z'),
        'exitCode' => $exit, 'timedOut' => $timedOut, 'stdout' => $stdout, 'stderr' => $stderr];
};
try {
    file_put_contents($folder . '/leaf.pem', $pem('CERTIFICATE', $leaf));
    file_put_contents($folder . '/issuer.pem', $pem('CERTIFICATE', $issuer));
    if ($crl !== null) { file_put_contents($folder . '/revoked.crl.pem', $pem('X509 CRL', $crl)); }
    $version = $run([$openssl, 'version']);
    $setup = $run([$openssl, 'verify', '-CAfile', $folder . '/issuer.pem', $folder . '/leaf.pem']);
    if ($version['exitCode'] !== 0 || $setup['exitCode'] !== 0 ||
        !str_contains($setup['stdout'], '/leaf.pem: OK')) {
        throw new RuntimeException('Native PKIX setup failed');
    }
    $parsed = openssl_x509_parse($pem('CERTIFICATE', $leaf));
    $network = [];
    if ($variant === 'certificate-revoked') {
        $failure = $run([$openssl, 'verify', '-CAfile', $folder . '/issuer.pem',
            '-CRLfile', $folder . '/revoked.crl.pem', '-crl_check', $folder . '/leaf.pem']);
        $errorCode = 23; $reason = 'CERTIFICATE_REVOKED';
        if ($failure['exitCode'] !== 2 ||
            !preg_match('/\berror 23 at 0 depth lookup: certificate revoked\b/i', $failure['stderr'])) {
            throw new RuntimeException('Revocation control not detected');
        }
    } else {
        $extensions = $parsed['extensions'];
        $serial = strtolower($parsed['serialNumberHex']);
        $prefix = 'http://samlscope-reference-suite:18481/samlscope-revocation/' . ltrim($serial, '0');
        $urls = [$prefix . '/unavailable.crl', $prefix . '/unavailable.ocsp'];
        if (!str_contains($extensions['crlDistributionPoints'] ?? '', $urls[0]) ||
            !str_contains($extensions['authorityInfoAccess'] ?? '', $urls[1])) {
            throw new RuntimeException('Certificate CDP/AIA bindings differ');
        }
        // These changes are confined to the diagnostic process and do not alter product configuration.
        foreach (['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'all_proxy'] as $name) {
            putenv($name . '=');
        }
        putenv('no_proxy=*'); putenv('NO_PROXY=*');
        foreach ($urls as $url) {
            $probe = $run(['/usr/bin/curl', '--noproxy', '*', '--connect-timeout', '1',
                '--max-time', '2', '--silent', '--show-error', $url]);
            if ($probe['exitCode'] !== 7 || !str_contains($probe['stderr'], 'curl: (7)')) {
                throw new RuntimeException('Actual certificate revocation endpoint not closed');
            }
            $probe['url'] = $url; $network[] = $probe;
        }
        // The bounded native GETs above are the real CDP/AIA lookup. This developer
        // mutant requires revocation evidence after that failed lookup and fails closed.
        // No missing-CRL-only finding is emitted without both original network failures.
        $failure = $run([$openssl, 'verify', '-CAfile', $folder . '/issuer.pem',
            '-crl_check', $folder . '/leaf.pem']);
        $errorCode = 3; $reason = 'UNDETERMINED_REVOCATION_STATUS';
        if ($failure['exitCode'] !== 2 ||
            !preg_match('/\berror 3 at 0 depth lookup: unable to get certificate CRL\b/i', $failure['stderr']) ||
            count($network) !== 2) {
            throw new RuntimeException('Failed revocation lookup was not detected');
        }
    }
    $sourceHashes = [];
    foreach ($input['sourcePaths'] as $name => $path) { $sourceHashes[$name] = hash_file('sha256', $path); }
    echo json_encode(['schema' => 'samlscope-simplesamlphp-openssl-certificate-check-calibration-v1',
        'counterfactualCalibrationOnly' => true, 'controlsAdopted' => false, 'actualProductFinding' => false,
        'runId' => $input['runId'], 'targetMetadataSha256' => $input['targetMetadataSha256'],
        'checkerSourceSha256' => $input['checkerSourceSha256'], 'nativePhpOpenSslVersion' => OPENSSL_VERSION_TEXT,
        'nativeOpenSslBinarySha256' => hash_file('sha256', $openssl), 'nativeOpenSslVersion' => $version,
        'nativeSourceHashes' => $sourceHashes,
        'records' => [['variant' => $variant, 'requestReference' => $input['requestReference'],
            'requestId' => $input['requestId'], 'requestSha256' => hash('sha256', $request),
            'fixtureSha256' => hash('sha256', $fixture), 'certificateSha256' => hash('sha256', $leaf),
            'issuerCertificateSha256' => hash('sha256', $issuer),
            'crlSha256' => $crl === null ? null : hash('sha256', $crl),
            'certificateSerialHex' => strtolower($parsed['serialNumberHex']),
            'nativeSignatureVerified' => true, 'nativeSignatureMethod' => 'SimpleSAML\\Module\\saml\\Message::checkSign',
            'signatureVerifiedAt' => $signatureVerifiedAt, 'setup' => $setup,
            'selectedOperation' => $failure['command'], 'failure' => $failure, 'network' => $network,
            'revocationPolicy' => $variant === 'certificate-revocation-unreachable' ?
                ['lookupSource' => 'native-curl-certificate-CDP/AIA', 'lookupOutcome' => 'UNAVAILABLE',
                 'requireRevocationEvidence' => true, 'failureMode' => 'fail-closed'] : null,
            'accepted' => false, 'errorCode' => $errorCode, 'reason' => $reason,
            'counterfactualCalibrationOnly' => true]]], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
} finally {
    foreach (['leaf.pem', 'issuer.pem', 'revoked.crl.pem'] as $name) { @unlink($folder . '/' . $name); }
    if (!rmdir($folder)) { throw new RuntimeException('Public temporary material cleanup failed'); }
}
