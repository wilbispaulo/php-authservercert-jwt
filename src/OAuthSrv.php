<?php

namespace AuthServerJwt;

use DateTime;
use DateTimeZone;
use Jose\Component\Core\JWK;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Serializer\CompactSerializer;

class OAuthSrv
{
    private string $privatePEM;
    private JWK $privateJWK;
    private $claims = [];

    public function __construct(
        private string $clientAud,
        private string $pathToP12,
        private string $secretCert
    ) {
        if (count($p12 = glob($this->pathToP12)) > 0) {
            $this->setPrivateKeyP12($p12[0]);
        } else {
            var_dump($this->pathToP12);
            die();
        }
    }
    private function setPrivateKeyP12(string $pathToP12)
    {
        $certP12 = file_get_contents($pathToP12);
        openssl_pkcs12_read($certP12, $certPEM, $this->secretCert);
        $this->privatePEM = $certPEM['pkey'];
        $this->setJWKPrivateKey();
    }

    private function setJWKPrivateKey()
    {
        $this->privateJWK = JWKFactory::createFromKey(
            $this->privatePEM,
            null,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
    }

    public function genCredentials(string $secret): array
    {
        $timeCred = (new DateTime('now', new DateTimeZone('America/Sao_Paulo')))->getTimestamp();
        $clientId = self::uuidv4();
        $credentialPlainText = $this->clientAud . '#' . $clientId . '#' . (string)$timeCred . '%' . $secret;
        $clientSecret = base64_encode(password_hash($credentialPlainText, PASSWORD_BCRYPT));

        return [
            'credential_time' => $timeCred,
            'client_aud' => $this->clientAud,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];
    }

    public function tokenJWT(string $issuer, int $tokenExp, array $scope): string
    {
        $baseTime = time();
        $this->claims = [
            'iat' => $baseTime,
            'nbf' => $baseTime,
            'exp' => $baseTime + $tokenExp,
            'iss' => $issuer,
            'aud' => $this->clientAud,
            'scope' => $scope,
        ];
        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new RS256]));
        $payload = json_encode($this->claims);

        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature(
                $this->privateJWK,
                [
                    'alg' => 'RS256',
                    'typ' => 'JWT',
                ]
            )
            ->build();
        $serializer = new CompactSerializer;
        return (new CompactSerializer)->serialize($jws, 0);
    }

    public function getClaims()
    {
        return $this->claims;
    }

    public static function uuidv4(): string
    {
        $data = random_bytes(16);

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
