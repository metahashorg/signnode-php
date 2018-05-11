<?php
ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
header('Access-Control-Allow-Origin: *');

define('ROOTDIR', dirname(__DIR__) .'/');

function IncNonce($from){
	if (!is_file(ROOTDIR . 'includes/nonce.json')){
		$nonceArr = array($from => 1);
		if (file_put_contents(ROOTDIR . 'includes/nonce.json', json_encode($nonceArr)) === false){
			return false;
		} else {
			return 1;
		}
	}
	$nonceArr = file_get_contents(ROOTDIR . 'includes/nonce.json');
	if ($nonceArr == ''){
		$nonceArr = array($from => 0);
	} else {
		$nonceArr = json_decode($nonceArr, true);
		if (is_null($nonceArr)){
			return false;
		}
	}

	$nonce = isset($nonceArr[$from]) ? ($nonceArr[$from] + 1) : 1;
	$nonceArr[$from] = $nonce;
	if (file_put_contents(ROOTDIR . 'includes/nonce.json', json_encode($nonceArr)) === false){
		return false;
	} else {
		return $nonce;
	}
}

function AddressStandart($from){
	if (strlen($from) != 52){
		return false;
	}
	if (substr($from, 0, 3) != '0x0'){
		return false;
	}
	if (preg_match('/^[a-z0-9]+$/si', $from) == 0){
		return false;
	}
	return true;
}

function CheckAdress($from){
	if (AddressStandart($from)){
		return is_file(ROOTDIR . 'keys/' . $from . '.key');
	}
	return false;
}

function mhcCreateAddress($data){
	$crypto  = new Ecdsa16();
	$keys    = $crypto->getKey();
	$address = $crypto->getAdress($keys['public']);
	if (file_put_contents(ROOTDIR . 'keys/' . $address . '.key', $keys['private']) === false){
		echo json_encode(array('error' => true, 'msg' => 'CANT_SAVE_KEY'));
	} else {
		echo json_encode(array('error' => false, 'address' => $address));
	}
}

function mhcVerify($data){
	if (!isset($data['params'])){
		echo json_encode(array('error' => true, 'msg' => 'NO_PARAMS'));
		exit;
	}
	if (!isset($data['params']['data'])){
		echo json_encode(array('error' => true, 'msg' => 'NO_DATA_IN_PARAMS'));
		exit;
	}

	if (!(isset($data['params']['data']['to']) and isset($data['params']['data']['value']) and
		isset($data['params']['data']['fee']) and isset($data['params']['data']['nonce']) and 
		isset($data['params']['data']['data']))){
		echo json_encode(array('error' => true, 'msg' => 'NOT_ALL_PARAMS_IN_DATA'));
		exit;
	}

	if(!isset($data['params']['pubkey'])){
		echo json_encode(array('error' => true, 'msg' => 'NO_PUBKEY_IN_PARAMS'));
		exit;
	}
	if(!isset($data['params']['sign'])){
		echo json_encode(array('error' => true, 'msg' => 'NO_SIGN_IN_PARAMS'));
		exit;
	}

	$signData = $data['params']['data']['to'] . $data['params']['data']['value'] . 
				$data['params']['data']['fee'] . $data['params']['data']['nonce'] . 
				$data['params']['data']['data']; 

	$crypt = new Ecdsa16();
	if (!$crypt->verify($data['params']['sign'], $signData, $data['params']['pubkey'])){
		echo json_encode(array('error' => true, 'msg' => 'WRONG_SIGNATURE')); 
		exit;
	} else {
		echo json_encode(array('error' => false, 'msg' => 'OK_SIGN')); 
		exit;		
	}
}

function mhcSendTransaction($data, $urlCore){
	$retArr  = array('id' => $data['id'], 'jsonrpc' => $data['jsonrpc'], 'error' => null);
	if (!isset($data['params'])){
		$retArr['error'] = true;
		return json_encode($retArr);
	}

	$postData = array('version' => '1.0.0', 'method' => 'mh_sendTransaction', 'id'=>$data['id'], 'jsonrpc' => $data['jsonrpc'], 'params' => array());
	
	$proxyHeader = array('X-Real-IP: ' . $_SERVER['SERVER_ADDR'], 
	                     'X-Forwarded-For: ' . $_SERVER['REMOTE_ADDR'] . ', ' . $_SERVER['SERVER_ADDR']);


	$crypto = new Ecdsa16();
	foreach ($data['params'] as $key => $value) {
		if (!(isset($value['from']) and isset($value['to']) and isset($value['fee']) and isset($value['value']) and 
			  isset($value['data']))){			
			$retArr['error'] = true;
			return json_encode($retArr);
		}

		if (!CheckAdress($value['from'])){
			$retArr['error'] = true;
			return json_encode($retArr);
		}

		$nonce = IncNonce($value['from']);
		if ($nonce === false){
			$retArr['error'] = true;
			return json_encode($retArr);			
		}

		
		$signData  = $value['from'] . $value['to'] . $value['fee'];
		$signData .= $value['value'] . $value['data'] . $nonce;
		
		$privateKey = file_get_contents(ROOTDIR . 'keys/' . $value['from'] . '.key');

		if ($crypto->is_base64_encoded($privateKey)){
			$privateKey = bin2hex(base64_decode($privateKey));
		}

		$sign = $crypto->sign($signData, $privateKey);
		$publicKey  = $crypto->privateToPublic($privateKey);
		$value['publicKey']   = $publicKey;
		$value['nonce']       = $nonce;
		$value['signature']   = $sign;
		$value['hash']   = hash('sha256', hash('sha256', $signData));
		$postData['params'][] = $value;
	}

	$postData = json_encode($postData);
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curl, CURLOPT_POST, 1);
	curl_setopt($curl, CURLOPT_HTTPGET, false);
	curl_setopt($curl, CURLOPT_POSTFIELDS, $postData);
	curl_setopt($curl, CURLOPT_HTTPHEADER, $proxyHeader);
	curl_setopt($curl, CURLOPT_URL, $urlCore);
	$res = curl_exec($curl);
	return $res;
}

$postData = file_get_contents('php://input');
$req_dump = $_SERVER['REMOTE_ADDR'] . ' - ' . time() . ' - ' . $postData . "\n";
file_put_contents(ROOTDIR . 'logs/request.log', $req_dump, FILE_APPEND);

if ($postData == ''){
	echo json_encode(array('err' => true, 'msg' => 'empty post data')); exit;
}

$data = json_decode($postData, true);
if (is_null($data)){
	echo json_encode(array('err' => true, 'msg' => 'no valid json'));
	exit;
}

include_once (ROOTDIR . 'includes/vendor/autoload.php');
// include_once (ROOTDIR . 'includes/Ecdsa.php');
include_once (ROOTDIR . 'includes/Ecdsa16.php');
include_once (ROOTDIR . 'includes/config.php');

if (!isset($data['method'])){
	echo json_encode(array('err' => true, 'msg' => 'no method in data')); exit;
}

switch ($data['method']) {
	case 'mhc_verify':
		mhcVerify($data);
		exit;
	case 'mh_sendTransaction':
		echo mhcSendTransaction($data, $urlCore);
		exit;
	case 'mh_createAddress':
		mhcCreateAddress($data);
		exit;
	default:
		echo json_encode(array('err' => true, 'msg' => 'wrong method in data')); exit;
}
?>