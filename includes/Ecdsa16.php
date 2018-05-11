<?php
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

class Ecdsa16
{
	private $adapter;
	private $generator;

	public function __construct()
	{
		$this->adapter = EccFactory::getAdapter();
		$this->generator = EccFactory::getSecgCurves()->generator256r1();
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
		//$result['private'] = base64_encode($data_private);
		$result['private'] = '0x'.bin2hex($data_private);

		$public = $private->getPublicKey();
		$serializer_public = new DerPublicKeySerializer($this->adapter);
		$data_public = $serializer_public->serialize($public);
		//$result['public'] = base64_encode($data_public);
		$result['public'] = '0x'.bin2hex($data_public);

		return $result;
	}

	public function privateToPublic($private_key)
	{
		$serializer_private = new DerPrivateKeySerializer($this->adapter);
		$private_key = $this->parse_base16($private_key);
		$private_key = $this->hex2bin_custom($private_key);
		$key = $serializer_private->parse($private_key);

		$public = $key->getPublicKey();
		$serializer_public = new DerPublicKeySerializer($this->adapter);
		$data_public = $serializer_public->serialize($public);
		$result = '0x'.bin2hex($data_public);

		return $result;
	}

	public function parsePrivatePem($private_key)
	{
		$serializer_private_der = new DerPrivateKeySerializer($this->adapter);
		$serializer_private_pem = new PemPrivateKeySerializer($serializer_private_der);
		$key = $serializer_private_pem->parse($private_key);
		$result = $serializer_private_der->serialize($key);
		$result = '0x'.bin2hex($result);

		return $result;
	}

	public function parsePublicPem($public_key)
	{
		$serializer_public_der = new DerPublicKeySerializer($this->adapter);
		$serializer_public_pem = new PemPublicKeySerializer($serializer_public_der);
		$key = $serializer_public_pem->parse($public_key);
		$result = $serializer_public_der->serialize($key);
		$result = '0x'.bin2hex($result);

		return $result;
	}

	public function sign($data, $private_key, $rand = false, $algo = 'sha256')
	{
		$serializer_private = new DerPrivateKeySerializer($this->adapter);
		$private_key = $this->parse_base16($private_key);
		$private_key = $this->hex2bin_custom($private_key);
		$key = $serializer_private->parse($private_key);

		$signer = new Signer($this->adapter);
		$hash = $signer->hashData($this->generator, $algo, $data);

		if(!$rand)
		{
    		$random = RandomGeneratorFactory::getHmacRandomGenerator($key, $hash, $algo);
		}
		else
		{
			$random = RandomGeneratorFactory::getRandomGenerator();
		}

		$randomK = $random->generate($this->generator->getOrder());
		$signature = $signer->sign($key, $hash, $randomK);

		$serializer = new DerSignatureSerializer();
		$serialized_sign = $serializer->serialize($signature);

		return '0x'.bin2hex($serialized_sign);
	}

	public function verify($sign, $data, $public_key, $algo = 'sha256')
	{
		$signer = new Signer($this->adapter);
		$serializer = new DerSignatureSerializer();
		$serializer_public = new DerPublicKeySerializer($this->adapter);

		$public_key = $this->parse_base16($public_key);
		$public_key = $this->hex2bin_custom($public_key);
		$key = $serializer_public->parse($public_key);
		$hash = $signer->hashData($this->generator, $algo, $data);

		$sign = $this->parse_base16($sign);
		$sign = $this->hex2bin_custom($sign);
		$serialized_sign = $serializer->parse($sign);
		$check = $signer->verify($key, $serialized_sign, $hash);

		return ($signer->verify($key, $serialized_sign, $hash))?true:false;
	}

	public function checkPublicKey($key)
	{
		$result = false;

		try
		{
			$serializer_public = new DerPublicKeySerializer($this->adapter);
			$key = $this->parse_base16($key);
			$key = $this->hex2bin_custom($key);
			$key_parse = $serializer_public->parse($key);
			if(is_object($key_parse) && $key_parse instanceof Mdanter\Ecc\Crypto\Key\PublicKey)
			{
				$result = true;
			}
		}
		catch(Exception $e)
		{
			//empty
		}

		return $result;
	}

	public function getAdress($key, $net = '00')
	{
		$code = '';

		$serializer_public = new DerPublicKeySerializer($this->adapter);
		$key = $this->parse_base16($key);
		$key = $this->hex2bin_custom($key);
		$key = $serializer_public->parse($key);
	
		$x = gmp_strval($key->getPoint()->getX(), 16);
        $xlen = 64 - strlen($x);
        $x = ($xlen > 0)?str_repeat('0', $xlen).$x:$x;
        $y = gmp_strval($key->getPoint()->getY(), 16);
        $ylen = 64 - strlen($y);
        $y = ($ylen > 0)?str_repeat('0', $ylen).$y:$y;

		$code = '04'.$x.$y;
		$code = $this->hex2bin_custom($code);
		$code = $this->hex2bin_custom(hash('sha256', $code));
		$code = $net.hash('ripemd160', $code);
		$code = $this->hex2bin_custom($code);
		$hash_summ = $this->hex2bin_custom(hash('sha256', $code));
		$hash_summ = hash('sha256', $hash_summ);
		$hash_summ = substr($hash_summ, 0, 8);
		$code = bin2hex($code).$hash_summ;

		return '0x'.$code;
	}

	public function hex2bin_custom($str)
	{
		$sbin = "";
		$len = strlen( $str );
		for ( $i = 0; $i < $len; $i += 2 ) {
			$sbin .= pack("H*", substr( $str, $i, 2 ) );
		}

		return $sbin;
	}

	public function is_base64_encoded($data)
	{
		$data = str_replace("\r\n", '', $data);
		$chars = array('+', '=', '/', '-');
		$n = 0;
		foreach($chars as $val)
		{
			if(strstr($data, $val))
			{
				$n++;
			}
		}

		return ($n > 0 && base64_encode(base64_decode($data, true)) === $data)?true:false;
	}

	public function to_base16($string)
	{
		return (substr($string, 0, 2) === '0x')?$string:'0x'.$string;
	}

	public function parse_base16($string)
	{
		return (substr($string, 0, 2) === '0x')?substr($string, 2):$string;
	}
}

?>