<?php
/** Public projection only. Native private material is loaded in memory, never emitted. */
// Reproduce the public metadata GET context, never a credential/header context.
$publicContext = ['method'=>'GET','scheme'=>'http','host'=>'localhost','port'=>18380,
                  'path'=>'/simplesaml/module.php/saml/idp/metadata'];
$_SERVER['REQUEST_METHOD'] = $publicContext['method'];
$_SERVER['REQUEST_SCHEME'] = $publicContext['scheme'];
$_SERVER['HTTP_HOST'] = $publicContext['host'].':'.$publicContext['port'];
$_SERVER['SERVER_NAME'] = $publicContext['host'];
$_SERVER['SERVER_PORT'] = (string)$publicContext['port'];
$_SERVER['HTTPS'] = 'off';
$_SERVER['REQUEST_URI'] = $publicContext['path'];
$_SERVER['SCRIPT_NAME'] = '/simplesaml/module.php';
$_SERVER['PHP_SELF'] = '/simplesaml/module.php';
require '/var/simplesamlphp/lib/_autoload.php';
try {
    $entity = 'http://localhost:18380/idp';
    $handler = \SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
    $config = $handler->getMetaDataConfig($entity, 'saml20-idp-hosted');
    $generated = \SimpleSAML\Module\saml\IdP\SAML2::getHostedMetadata($entity, $handler);
    $builder = new \SimpleSAML\Metadata\SAMLBuilder($entity);
    $builder->addMetadataIdP20($generated);
    $builder->addOrganizationInfo($generated);
    $nativeProduced = $builder->getEntityDescriptorText();
    $crypto = new \SimpleSAML\Utils\Crypto();
    $public = [];
    foreach (['entityid','metadata-set','SingleSignOnService','SingleLogoutService','ArtifactResolutionService','NameIDFormat','keys','sign.authnrequest','redirect.sign'] as $field) {
        if (array_key_exists($field, $generated)) $public[$field] = $generated[$field];
    }
    $rows = [];
    foreach (['', 'new_', 'https.'] as $prefix) {
        $certificate = $crypto->loadPublicKey($config, false, $prefix);
        $private = $crypto->loadPrivateKey($config, false, $prefix);
        $row = ['prefix'=>$prefix,'publicCertificatePresent'=>$certificate!==null,'privateCredentialPresent'=>$private!==null];
        if ($certificate !== null) {
            $der = base64_decode($certificate['certData'], true);
            if ($der === false) throw new \RuntimeException('Invalid native public certificate');
            $parsed = openssl_x509_read("-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der),64,"\n")."-----END CERTIFICATE-----\n");
            if ($parsed === false) throw new \RuntimeException('Invalid native public certificate');
            $key = openssl_pkey_get_public($parsed);
            if ($key === false) throw new \RuntimeException('Invalid public key');
            $details = openssl_pkey_get_details($key);
            $row['certificateDerBase64'] = base64_encode($der);
            $row['certificateSha256'] = hash('sha256', $der);
            $row['certificatePublicSpkiPem'] = $details['key'];
            $row['certificatePublicSpkiPemSha256'] = hash('sha256', $details['key']);
            unset($certificate,$parsed,$key,$details);
        }
        if ($private !== null) {
            $key = openssl_pkey_get_private($private['PEM'], $private['password'] ?? '');
            if ($key === false) throw new \RuntimeException('Native credential unavailable');
            $details = openssl_pkey_get_details($key);
            $row['nativePrivateCredentialPublicSpkiPem'] = $details['key'];
            $row['nativePrivateCredentialPublicSpkiPemSha256'] = hash('sha256', $details['key']);
            unset($private,$key,$details);
        }
        $rows[] = $row;
    }
    $peers = [];
    foreach ($handler->getList('saml20-sp-remote', false) as $peerEntity => $unusedPublicMetadata) {
        $peer = $handler->getMetaDataConfig($peerEntity, 'saml20-sp-remote');
        $override = $crypto->loadPrivateKey($peer, false, 'signature.');
        $row = ['entityId'=>$peerEntity,'signatureOverridePresent'=>$override!==null,
                'sharedEncryptionOverridePresent'=>$peer->hasValue('sharedkey')];
        if ($override !== null) {
            $key = openssl_pkey_get_private($override['PEM'], $override['password'] ?? '');
            if ($key === false) throw new \RuntimeException('Native peer credential unavailable');
            $details = openssl_pkey_get_details($key);
            $row['signatureOverridePublicSpkiPem'] = $details['key'];
            unset($override,$key,$details);
        }
        $peers[] = $row;
    }
    usort($peers, static fn(array $a,array $b):int => strcmp($a['entityId'],$b['entityId']));
    $classes = [
        'native-idp.php'=>\SimpleSAML\Module\saml\IdP\SAML2::class,
        'native-builder.php'=>\SimpleSAML\Metadata\SAMLBuilder::class,
        'native-configuration.php'=>\SimpleSAML\Configuration::class,
        'native-crypto.php'=>\SimpleSAML\Utils\Crypto::class,
        'native-handler.php'=>get_class($handler),
        'native-message.php'=>\SimpleSAML\Module\saml\Message::class,
        'native-controller.php'=>\SimpleSAML\Module\saml\Controller\Metadata::class,
    ];
    $loaded = [];
    foreach ($classes as $name=>$class) {
        $reflection = new \ReflectionClass($class); $file = $reflection->getFileName();
        $loaded[] = ['logicalFile'=>$name,'class'=>$class,'file'=>$file,'sha256'=>hash_file('sha256',$file)];
    }
    $global = \SimpleSAML\Configuration::getInstance(); $sources = [];
    foreach ($global->getOptionalArray('metadata.sources', []) as $source) {
        $sources[] = ['type'=>$source['type']??null,'configurationHash'=>hash('sha256',serialize($source))];
    }
    $hashes = [];
    foreach (['/var/simplesamlphp/config/config.php','/var/simplesamlphp/metadata/saml20-idp-hosted.php','/var/simplesamlphp/metadata/saml20-sp-remote.php'] as $file) {
        $hashes[] = ['file'=>$file,'sha256'=>hash_file('sha256',$file)];
    }
    $flags = [];
    foreach (['saml20.ecp','saml20.hok.assertion','saml20.sendartifact','metadata.sign.enable'] as $field) {
        $flags[$field] = $config->getOptionalBoolean($field,false);
    }
    echo json_encode(['schema'=>'samlscope-ssp-public-publisher-state-v1','entityId'=>$entity,
        'recordedAt'=>gmdate('Y-m-d\TH:i:s\Z'),'publicRequestContext'=>$publicContext,'publicNativeMetadata'=>$public,'currentCredentials'=>$rows,
        'remotePeers'=>$peers,'loadedClasses'=>$loaded,'metadataSources'=>$sources,'configurationHashes'=>$hashes,
        'roleFeatureFlags'=>$flags,'nativeProducedMetadataXmlBase64'=>base64_encode($nativeProduced),
        'nativeProducedMetadataSha256'=>hash('sha256',$nativeProduced)],JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES),"\n";
} catch (\Throwable $failure) {
    // Native exceptions may contain credential paths or contents; retain only their class.
    echo json_encode(['schema'=>'samlscope-ssp-public-publisher-state-error-v1','exceptionClass'=>get_class($failure)]),"\n";
    exit(2);
}
