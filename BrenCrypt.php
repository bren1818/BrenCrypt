<?php
	class BrenCrypt{
		private $key;
		private $iv;
		
		private $enableTimeout;
		private $timeout;
		private $enableEncryption;

		private $enableKeys;
		private $publicKey;
		private $privateKey;
		private $enableTokens;
		private $token;
		
		private $connection;
		private $throwExceptions;
		
		
		function __construct($conn = null) {
			$this->enableEncryption = true;
			$this->enableTimeout = false;
			$this->enableKeys = false;
			$this->enableTokens = false;
			$this->connection = $conn; //set DB Connection
			$this->throwExceptions = false;
			
			$this->iv = mcrypt_create_iv(32);
		}
		
		function encrypt($input) {
			if( $this->enableEncryption == true && $this->enableTimeout == false && $this->enableKeys == false && $this->enableTokens == false){
				/*Just simple encryption */
				if( $this->key == "" || strlen($this->key) < 5 ){
					 throw new Exception('Key too short or empty');
				}else{
					return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->key, $input, MCRYPT_MODE_ECB, $this->iv));
				}
			}else{
				/*Construct a "package" to send */
				
				$package = array();
				
				if(  $this->enableTimeout == true ){
					$package[] = array("signed" => time() );
				}
				
				if(  $this->enableKeys ){
					$package[] = array("pubKey" => $this->publicKey );
				}
				
				if( $this->enableTokens == true ){
					$package[] = array("token" => $this->token );
				}
				
				if( $this->enableEncryption == true ){
					$package[] = array("payload" => base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->key, $input, MCRYPT_MODE_ECB, $this->iv)) );
				}else{
					$package[] = array("payload" => $input );
				}
				
				//this should be done last
				if(  $this->enableKeys ){
					$package[] = array("signature" => hash_hmac('ripemd160',$package,$this->privateKey) );
				}
				
				return $package;
			}
		}
		
		function decrypt($input) {
			if( $this->enableEncryption == true && $this->enableTimeout == false && $this->enableKeys == false && $this->enableTokens == false){
				/*Just simple Decrypt*/
				if( $this->key == "" || strlen($this->key) < 5 ){
					throw new Exception('Key too short or empty');
				}else{
					return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->key, base64_decode($input), MCRYPT_MODE_ECB, $this->iv));
				}
			}else{
				/*Need to De construct Package*/
				$withinLimit = 0;
				$unlocked = 0;
				$tokenOK = 0;
				$decrypted = 1;
				$payload = null;
				
				if( $this->enableTimeout == true ){
					$signed  = $input["signed"]; //signing time
					$currentTime = time();
					$difference = ($currentTime - $signed);
					
					if( $difference >= 0 && $difference < $this->timeout ){
						$withinLimit = 1;
					}else{
						throw new Exception('package time outside time limit');
					}
				}else{
					$withinLimit = 1;
				}
				
				if( $this->enableKeys ){		
					$signature = $input["signature"];
					$checkD = $input;
					unset( $checkD["signature"] );
					
					//look up privateKey based on publicKey--------------------------------
					$pubKey = $input["pubKey"];
					$privKey = ""; //call lookup function
					
					
					if( hash_hmac('ripemd160',$checkD,$privKey) == $signature ){
						$unlocked = 1;
					}else{
						throw new Exception('signature invalid');
					}
				}else{
					$unlocked = 1;
				}
				
				if( $this->enableTokens == true ){
					$token =  $input["token"];
					//look up if token is used
					$tokenAvailable = 0;
					//do lookup -------------------------------------------
					
					if( $tokenAvailable ){
						$tokenOK = 1;
					}else{
						throw new Exception('token invalid');
						$tokenOK = 0;
					}
				
				}
				
				if( $this->enableEncryption == true){
					if( $tokenOK && $unlocked && $withinLimit ){
						$decrypted = 1;
					}else{
						$decrypted = 0;
						throw new Exception('prior tests failed. Decryption disabled');
					}
				}
				
				if( $tokenOK && $unlocked && $withinLimit && $decrypted ){
					if( $this->enableEncryption == true){
						$payload = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->key, base64_decode($input["payload"]), MCRYPT_MODE_ECB, $this->iv));
					}else{
						$payload = $input["payload"];
					}
				}
				
				return $payload;
				
			}
		}
		
		/*Boolean*/
		function getEnableTimeout(){
			return $this->enableTimeout;
		}
		
		/*Boolean*/
		function setEnableTimeout($enableTimeout = true){
			$this->enableTimeout = $enableTimeout;
		}

		/*Seconds*/
		function getTimeout(){
			return $this->timeout;
		}

		/*Seconds*/
		function setTimeout($timeout){
			$this->timeout = $timeout;
		}

		
		/*Boolean*/
		function getEnableEncryption(){
			return $this->enableEncryption;
		}
		
		/*Boolean*/
		function setEnableEncryption($enableEncryption = true){
			$this->enableEncryption = $enableEncryption;
		}

		/*
		function getKey(){
			return $this->key;
		}
		*/
		
		function setKey($key){
			$this->key = hash('sha256',$key,TRUE);
		}

		/*Boolean*/
		function getEnableKeys(){
			return $this->enableKeys;
		}
		
		/*Boolean*/
		function setEnableKeys($enableKeys = true){
			$this->enableKeys = $enableKeys;
		}

		function getPublicKey(){
			return $this->publicKey;
		}

		/*String*/
		function setPublicKey($publicKey){
			$this->publicKey = $publicKey;
		}
		
		/*
		function getPrivateKey(){
			return $this->privateKey;
		}
		*/
		
		/*String*/
		function setPrivateKey($privateKey){
			$this->privateKey = $privateKey;
		}

		function getEnableTokens(){
			return $this->enableTokens;
		}

		/*Boolean*/
		function setEnableTokens($enableTokens = true){
			$this->enableTokens = $enableTokens;
		}

		
		function getToken(){
			return $this->token;
		}

		/*String*/
		function setToken($token){
			$this->token = $token;
		}
		
		
		
	}
	
	
	
	class BToken{
		/***
			token, v
			used, i
			expiry, v
			
			CREATE TABLE  `btoken` (
			`id` INT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY,
			`token` VARCHAR( 45 ),
			`used` INTEGER,
			`expiry` VARCHAR( 45 )
			);
			
	
		***/
		private $id;
		private $connection;
		private $token;
		private $used;
		private $expiry;
		
		/*Constructor*/
		function __construct($databaseConnection=null){
			$this->connection = $databaseConnection;
		}
		
		function getToken(){
			return $this->token;
		}

		function setToken($token){
			$this->token = $token;
		}

		function getUsed(){
			return $this->used;
		}

		function setUsed($used){
			$this->used = $used;
		}

		function getExpiry(){
			return $this->expiry;
		}

		function setExpiry($expiry){
			$this->expiry = $expiry;
		}
		
		function save(){
			$id = $this->getId();
			$token = $this->getToken();
			$used = $this->getUsed();
			$expiry = $this->getExpiry();
			if( $this->connection ){
				if( $id != "" ){
					/*Perform Update Operation*/
					$query = $this->connection->prepare("UPDATE  `btoken` SET `token` = :token ,`used` = :used ,`expiry` = :expiry WHERE `id` = :id");
					$query->bindParam('token', $token);
					$query->bindParam('used', $used);
					$query->bindParam('expiry', $expiry);
					$query->bindParam('id', $id);
					if( $query->execute() ){
						return $id;
					}else{
						return -1;
					}

				}else{
					/*Perform Insert Operation*/
					$query = $this->connection->prepare("INSERT INTO `btoken` (`id`,`token`,`used`,`expiry`) VALUES (NULL,:token,:used,:expiry);");
					$query->bindParam(':token', $token);
					$query->bindParam(':used', $used);
					$query->bindParam(':expiry', $expiry);

					if( $query->execute() ){
						$this->setId( $this->connection->lastInsertId() );
						return $this->getId();
					}else{
						return -1;
					}	
				}
			}
		}

		function delete($id = null){
			if( $this->connection ){
				if( $id == null && $this->getToken() != ""){
					$id = $this->getToken();
				}

				/*Perform Query*/
				if( $id != "" ){
					$query = $this->connection->prepare("DELETE FROM `btoken` WHERE `token` = :id"); ////////////////////////////////////
					$query->bindParam(':id', $id);
					if( $query->execute() ){
						return 1;
					}else{
						return 0;
					}
				}
			}
		}
		
		function load($id = null){
			if( $this->connection ){
				if( $id == null && $this->getToken() != ""){
					$id = $this->getToken();
				}
				/*Perform Query*/
				if( $id != "" ){
					$query = $this->connection->prepare("SELECT * FROM `btoken` WHERE `token` = :id");/////////////////////////////////////
					$query->bindParam(':id', $id);
					if( $query->execute() ){
						$btoken = $query->fetchObject("btoken");
					}
					if( is_object( $btoken ) ){
						$btoken->setConnection( $this->connection );
					}
					return $btoken;
				}
			}
		}
		
		
		
		function clearExpiredTokens(){
			if( $this->connection ){
				/*TO DO*/
		
		
			}
		}
		
		
	}
	
	class BKeyin{
		/**
			pubKey, v
			privKey, v
			name, v
	
			CREATE TABLE  `bkeyin` (
			`id` INT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY,
			`pubKey` VARCHAR( 45 ),
			`privKey` VARCHAR( 45 ),
			`name` VARCHAR( 45 )
			);
		**/
		
		
		private $id;
		private $connection;
		private $pubKey;
		private $privKey;
		private $name;
		
		/*Constructor*/
		function __construct($databaseConnection=null){
			$this->connection = $databaseConnection;
		}

		/*Getters and Setters*/
		function getId(){
			return $this->id;
		}

		function setId($id){
			$this->id = $id;
		}

		function getConnection(){
			return $this->connection;
		}

		function setConnection($connection){
			$this->connection = $connection;
		}

		function getPubKey(){
			return $this->pubKey;
		}

		function setPubKey($pubKey){
			$this->pubKey = $pubKey;
		}

		function getPrivKey(){
			return $this->privKey;
		}

		function setPrivKey($privKey){
			$this->privKey = $privKey;
		}

		function getName(){
			return $this->name;
		}

		function setName($name){
			$this->name = $name;
		}
		
		/*Special Functions*/
		function loadByPublicKey($id = null){
			if( $this->connection ){
				if( $id == null && $this->getPubKey() != ""){
					$id = $this->getPubKey();
				}

				/*Perform Query*/
				if( $id != "" ){
					$query = $this->connection->prepare("SELECT * FROM `bkeyin` WHERE `pubKey` = :id");
					$query->bindParam(':id', $id);
					if( $query->execute() ){
						$bkeyin = $query->fetchObject("bkeyin");
					}
					if( is_object( $bkeyin ) ){
						$bkeyin->setConnection( $this->connection );
					}
					return $bkeyin;
				}
			}
		}
		
		
		/*Special Functions*/
		function loadByPrivateKey($id = null){
			if( $this->connection ){
				if( $id == null && $this->getPrivKey() != ""){
					$id = $this->getPrivKey();
				}

				/*Perform Query*/
				if( $id != "" ){
					$query = $this->connection->prepare("SELECT * FROM `bkeyin` WHERE `privKey` = :id");
					$query->bindParam(':id', $id);
					if( $query->execute() ){
						$bkeyin = $query->fetchObject("bkeyin");
					}
					if( is_object( $bkeyin ) ){
						$bkeyin->setConnection( $this->connection );
					}
					return $bkeyin;
				}
			}
		}
		
		
		function load($id = null){
			if( $this->connection ){
				if( $id == null && $this->getId() != ""){
					$id = $this->getId();
				}

				/*Perform Query*/
				if( $id != "" ){
					$query = $this->connection->prepare("SELECT * FROM `bkeyin` WHERE `id` = :id");
					$query->bindParam(':id', $id);
					if( $query->execute() ){
						$bkeyin = $query->fetchObject("bkeyin");
					}
					if( is_object( $bkeyin ) ){
						$bkeyin->setConnection( $this->connection );
					}
					return $bkeyin;
				}
			}
		}

		function save(){
			$id = $this->getId();
			$pubKey = $this->getPubKey();
			$privKey = $this->getPrivKey();
			$name = $this->getName();
			if( $this->connection ){
				if( $id != "" ){
					/*Perform Update Operation*/
					$query = $this->connection->prepare("UPDATE  `bkeyin` SET `pubKey` = :pubKey ,`privKey` = :privKey ,`name` = :name WHERE `id` = :id");
					$query->bindParam('pubKey', $pubKey);
					$query->bindParam('privKey', $privKey);
					$query->bindParam('name', $name);
					$query->bindParam('id', $id);
					if( $query->execute() ){
						return $id;
					}else{
						return -1;
					}

				}else{
					/*Perform Insert Operation*/
					$query = $this->connection->prepare("INSERT INTO `bkeyin` (`id`,`pubKey`,`privKey`,`name`) VALUES (NULL,:pubKey,:privKey,:name);");
					$query->bindParam(':pubKey', $pubKey);
					$query->bindParam(':privKey', $privKey);
					$query->bindParam(':name', $name);

					if( $query->execute() ){
						$this->setId( $this->connection->lastInsertId() );
						return $this->getId();
					}else{
						return -1;
					}	
				}
			}
		}
		
		function delete($id = null){
			if( $this->connection ){
				if( $id == null && $this->getId() != ""){
					$id = $this->getId();
				}

				/*Perform Query*/
				if( $id != "" ){
					$query = $this->connection->prepare("DELETE FROM `bkeyin` WHERE `id` = :id");
					$query->bindParam(':id', $id);
					if( $query->execute() ){
						return 1;
					}else{
						return 0;
					}
				}
			}
		}
			
	}
	
	
	
?>