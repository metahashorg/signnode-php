<?php
ini_set('error_reporting', E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
header('Access-Control-Allow-Origin: *');

define('ROOTDIR', dirname(__DIR__) .'/');

function mhcCreateAddress($data){
	$crypto  = new Ecdsa16();
	$keys    = $crypto->getKey();
	$address = $crypto->getAdress($keys['public']);
	if (file_put_contents(ROOTDIR . 'keys/' . $address, $keys['private'] . '.key') === false){
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

function mhcSendTransaction($data){

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

if (!isset($data['method'])){
	echo json_encode(array('err' => true, 'msg' => 'no method in data')); exit;
}

switch ($data['method']) {
	case 'mhc_verify':
		mhcVerify($data);
		exit;
	case 'mh_sendTransaction':
		mhcSendTransaction($data);
		exit;
	case 'mh_createAddress':
		mhcCreateAddress($data);
		exit;
	default:
		echo json_encode(array('err' => true, 'msg' => 'wrong method in data')); exit;
}
?>