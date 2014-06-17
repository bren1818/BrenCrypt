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
		private $tokenLifeSeconds;
		
		
		private $connection;
		private $throwExceptions;
		
		private $errors;
		private $errorCount;
		
		
		function __construct($conn = null) {
			$this->enableEncryption = true;
			$this->enableTimeout = false;
			$this->enableKeys = false;
			$this->enableTokens = false;
			$this->connection = $conn; //set DB Connection
			$this->throwExceptions = false;
			
			$this->iv = mcrypt_create_iv(32);
			$this->tokenLifeSeconds = 300;
			$this->errors = array();
			$this->errorCount = 0;
		}
		
		function encrypt($input) {
			if( $this->enableEncryption == true && $this->enableTimeout == false && $this->enableKeys == false && $this->enableTokens == false){
				/*Just simple encryption */
				if( $this->key == "" || strlen($this->key) < 5 ){
					$this->errorCount++;
					$this->addError("Encryption Key too short or empty");
					//throw new Exception('Key too short or empty');
				}else{
					return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->key, $input, MCRYPT_MODE_ECB, $this->iv));
				}
			}else{
				/*Construct a "package" to send */
				
				$package = array();
				$sanity = "";
				//calculate entire sanity
				if( $this->enableTimeout == true ){ $sanity.="1"; }else{ $sanity.="0"; }
				if( $this->enableKeys == true ){ $sanity.="1"; }else{ $sanity.="0"; }
				if( $this->enableTokens == true ){ $sanity.="1"; }else{ $sanity.="0"; }
				if( $this->enableEncryption == true){ $sanity.="1"; }else{ $sanity.="0"; }
				
				
				if(  $this->enableTimeout == true ){
					$package["ts"] = time() ;
				}
				
				if( $this->enableKeys ){
					$package["pubKey"] = $this->publicKey ;
				}
				
				if( $this->enableTokens == true ){
					$token = new BToken($this->connection);
					$token->setUsed(0);
					$token->setExpiry( time() + $this->tokenLifeSeconds ); // 5 mins from now
					if( $token->save() > 0 ){
						$this->token = $token->getToken();
						$package["token"] = $token->getToken() ;
						
					}else{
						//error cannot generate token
						$this->errorCount++;
						$this->addError("Cannot generate token.");
					}
				}
				
				if( $this->enableEncryption == true ){
					if(  $this->enableTimeout == true ){
						$package["payload"] = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($this->key.$sanity.$package["ts"]), $input, MCRYPT_MODE_ECB, $this->iv)) ;
					}else{
						$package["payload"] = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($this->key.$sanity), $input, MCRYPT_MODE_ECB, $this->iv)) ;
					}
				}else{
					$package["payload"] = $input ;
				}
				
				//this should be done last
				if(  $this->enableKeys ){
					$package["signature"] = hash_hmac('ripemd160', serialize($package), $this->privateKey.$sanity);
				}
				
				return $package;
			}
		}
		
		function decrypt($input) {
			if( $this->enableEncryption == true && $this->enableTimeout == false && $this->enableKeys == false && $this->enableTokens == false){
				/*Just simple Decrypt*/
				if( $this->key == "" || strlen($this->key) < 5 ){
					//throw new Exception('Key too short or empty');
					$this->errorCount++;
					$this->addError("Decryption Key too short or empty");
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
				
				$sanity  = "";
				//calculate entire string first
				//-timeout, keys, tokens, encryption
				if( $this->enableTimeout == true ){ $sanity.="1"; }else{ $sanity.="0"; }
				if( $this->enableKeys == true ){ $sanity.="1"; }else{ $sanity.="0"; }
				if( $this->enableTokens == true ){ $sanity.="1"; }else{ $sanity.="0"; }
				if( $this->enableEncryption == true){ $sanity.="1"; }else{ $sanity.="0"; }
				
				
				if( $this->enableTimeout == true ){
					$signed  = $input["ts"]; //signing time
					$currentTime = time();
					$difference = abs($currentTime - $signed);
					
					if( $difference >= 0 && $difference < $this->timeout ){
						if( $difference < 0 ){
							//packet from the future?
							$this->errorCount++;
							
							$this->addError("Packet has future time stamp.");
							
						}
						
						$withinLimit = 1;
					}else{
						//throw new Exception('package time outside time limit');
						$this->errorCount++;
				
						$this->addError("Packet arrived outside of acceptable time range.");
						
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
					
					$key = new BKeyin($this->connection);
					$key = $key->loadByPublicKey( $pubKey );	
				    $privKey = $key->getPrivKey(); 
					
					//append sanity?
					if( hash_hmac('ripemd160',serialize($checkD),$privKey.$sanity) == $signature ){
						$unlocked = 1;
					}else{
						$this->errorCount++;
						$this->addError("Private Key could not be located or was mismatched. Package signing could be incorrect");
						//key mismatch
						$unlocked = 0;
					}
					
				}else{
					$unlocked = 1;
					
				}
				
				if( $this->enableTokens == true ){
					$token =  $input["token"];
					//do lookup -------------------------------------------
					$tokenCheck = new BToken($this->connection);
					$tokenCheck = $tokenCheck->load( $token );
					
					//look up if token is used
					if( is_object($tokenCheck) && $tokenCheck->isValid() ){
						$tokenOK = 1;
					}else{
						$tokenOK = 0;
						$this->errorCount++;
						$this->addError("Token not found or already used.");
					}
				}else{
					$tokenOK = 1;
				}
				
				if( $this->enableEncryption == true){
					if( $tokenOK && $unlocked && $withinLimit ){
						$decrypted = 1;
					}else{
						$decrypted = 0;
						$this->errorCount++;
						$this->addError("Something mismatched cannot decrypt.");
					}
				}else{
					$decrypted = 1;
				}
				
				if( $tokenOK && $unlocked && $withinLimit && $decrypted ){
					if( $this->enableEncryption == true){
						if(  $this->enableTimeout == true ){
							$payload = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($this->key.$sanity.$input["ts"]), base64_decode($input["payload"]), MCRYPT_MODE_ECB, $this->iv));
						}else{
							$payload = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($this->key.$sanity), base64_decode($input["payload"]), MCRYPT_MODE_ECB, $this->iv));
						}
					}else{
						$payload = $input["payload"];
					}
				}else{
					//could set the payload to a message
					$this->errorCount++;
					
					//$this->addError("Something mismatched cannot decrypt.");
					
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
		
		
		function getErrors(){
			return $this->errors;
		}

		function setErrors($errors){
			$this->errors = $errors;
		}

		function getErrorCount(){
			return $this->errorCount;
		}

		function setErrorCount($errorCount){
			$this->errorCount = $errorCount;
		}
		
		function addError($error){
			array_push($this->errors, $error);
		}
		
	}
	
	
	
	class BToken{
		/***
			token, v
			used, i
			expiry, v
			
			CREATE TABLE  `btoken` (
			`id` INT NULL DEFAULT NULL AUTO_INCREMENT PRIMARY KEY,
			`token` VARCHAR( 155 ),
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
			
			$this->setToken( md5( time()."tokenGenerator!" ) );
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
		
		function isValid(){
			if( $this->id != "" && $this->getUsed() == 0 && ( time() < $this->getExpiry() ) ){
				$this->delete();
				return true;
			}else{
				$this->delete();
				return false;
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
			`pubKey` VARCHAR( 80 ),
			`privKey` VARCHAR( 80 ),
			`name` VARCHAR( 75 )
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