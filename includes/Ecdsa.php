<?php
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

function hex2bin_custom($str)
{
    $sbin = "";
    $len = strlen( $str );
    for ( $i = 0; $i < $len; $i += 2 ) {
        $sbin .= pack("H*", substr( $str, $i, 2 ) );
    }

    return $sbin;
}

class Ecdsa
{
	private $adapter;
	private $generator;

	public function __construct()
	{
		$this->adapter = EccFactory::getAdapter();
		$this->generator = EccFactory::getSecgCurves()->generator256r1();
		//$this->generator = EccFactory::getNistCurves()->generator256();
	}

	public function privateToPublic($private_key)
	{
		$serializer_private = new DerPrivateKeySerializer($this->adapter);
		$data_private = base64_decode($private_key);
		$private = $serializer_private->parse($data_private);
		$public = $private->getPublicKey();
		$serializer_public = new DerPublicKeySerializer($this->adapter);
		$data_public = $serializer_public->serialize($public);
		$result = base64_encode($data_public);
		return $result;
	}

	public function getAdress($key)
    {
        $code = '';

        $serializer_public = new DerPublicKeySerializer($this->adapter);
        $key = $serializer_public->parse(base64_decode($key));
        $x = gmp_strval($key->getPoint()->getX(), 16);
        $y = gmp_strval($key->getPoint()->getY(), 16);

        $code = '04'.$x.$y;
        $code = hex2bin_custom($code);
        $code = hex2bin_custom(hash('sha256', $code));
        $code = '00'.hash('ripemd160', $code);
        $code = hex2bin_custom($code);
        $hash_summ = hex2bin_custom(hash('sha256', $code));
        $hash_summ = hash('sha256', $hash_summ);
        $hash_summ = substr($hash_summ, 0, 8);
        $code = bin2hex($code).$hash_summ;

        return '0x'.$code;
    }

	public function getKey()
	{
		$result = array(
			'private' => null,
			'public' => null,
		);

		$private = $this->generator->createPrivateKey();
		$serializer_private = new DerPrivateKeySerializer($this->adapter);
		$data_private = $serializer_private->serialize($private);
		$result['private'] = base64_encode($data_private);

		$public = $private->getPublicKey();
		$serializer_public = new DerPublicKeySerializer($this->adapter);
		$data_public = $serializer_public->serialize($public);
		$result['public'] = base64_encode($data_public);

		return $result;
	}

	public function sign($data, $private_key, $rand = true, $algo = 'sha256')
	{
		$serializer_private = new DerPrivateKeySerializer($this->adapter);
		$key = $serializer_private->parse(base64_decode($private_key));

		$signer = new Signer($this->adapter);
		$hash = $signer->hashData($this->generator, $algo, $data);

		if($rand)
		{
			$random = RandomGeneratorFactory::getRandomGenerator();
		}
		else
		{
			$random = RandomGeneratorFactory::getHmacRandomGenerator($key, $hash, $algo);
		}

		$randomK = $random->generate($this->generator->getOrder());
		$signature = $signer->sign($key, $hash, $randomK);

		$serializer = new DerSignatureSerializer();
		$serialized_sign = $serializer->serialize($signature);

		return base64_encode($serialized_sign);
	}

	public function verify($sign, $data, $public_key, $algo = 'sha256')
	{
		$signer = new Signer($this->adapter);
		$serializer = new DerSignatureSerializer();
		$serializer_public = new DerPublicKeySerializer($this->adapter);

		$key = $serializer_public->parse(base64_decode($public_key));
		$hash = $signer->hashData($this->generator, $algo, $data);
		$serialized_sign = $serializer->parse(base64_decode($sign));
		$check = $signer->verify($key, $serialized_sign, $hash);

		return ($signer->verify($key, $serialized_sign, $hash))?true:false;
	}
}
?>