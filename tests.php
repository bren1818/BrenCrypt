<?php
	require_once "BrenCrypt.php";
	function pa( $item ){
		echo "<pre>".print_r($item,true)."</pre>";
	}
	
	//some instances may bark if date isn't set
	date_default_timezone_set("America/New_York");

	function getConnection() {
		$mode = 1;
		if( $mode == 1 ){
			$dbName = "encryptiontest"; 			//Database Name
			$dbUser = "root"; 						//Database User
			$dbPass = ""; 							//Database Password
			$dbHost = "localhost";
		}else if( $mode == 2 ){	
			$dbName = "stagingDB"; 			//Database Name
			$dbUser = "stagingUser"; 		//Database User
			$dbPass = "stagingPassword"; 	//Database Password
			$dbHost = "stagingHost";
		}else if( $mode == 3 ){
			//prod connection
		}
		
		$dbc = null;
		try {
			$dbc = new PDO('mysql:host='.$dbHost.';dbname='.$dbName, $dbUser, $dbPass);
			$dbc->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		}
		catch(PDOException $e) {
			echo "<h2>An error has occurred connecting to the database</h2>";
			echo "<p>".$e->getMessage()."</p>";
			file_put_contents('PDOErrorsLog.txt', $e->getMessage(), FILE_APPEND);
		}
		return $dbc;
	}
	
	
	$conn = getConnection();
	echo "<h1>Init Tests</h1>";
	echo "<h3>Simple Encryption</h3>";
	
	$bCrypt = new BrenCrypt($conn);
	
	$key = "MySuperSecretKey";
	$msg = "My Super important secret message.";
	
	echo "<p>Test with Encryption Key: ".$key."</p>";
	echo "<p>Encrypting Message: ".$msg."</p>";
	
	$bCrypt->setKey( $key );
	$encrypted = $bCrypt->encrypt( $msg );
	
	echo "<p>Encrypted message: ".$encrypted."</p>";
	
	echo "<h3>Simple Decryption</h3>";
	echo "<p>Decrypting: &ldquo;".$encrypted."&rdquo;</p>";
	$bCrypt->setKey("WrongKey");
	echo "<p>With <b>wrong</b> key: ".$bCrypt->decrypt( $encrypted )."</p>";
	$bCrypt->setKey($key);
	echo "<p>With <b>correct</b> key: ".$bCrypt->decrypt( $encrypted )."</p>";

	echo "<hr />";
	echo "<h1>Timeout test</h1>";
	echo "<p>Encrypting: ".$msg." with time period of 5 seconds</p>";
	
	$bCrypt->setEnableTimeout();
	$bCrypt->setTimeout(5); //5 seconds
	
	$encrypted = $bCrypt->encrypt( $msg );
	echo "<p>Payload:</p>";
	pa( $encrypted );
	
	echo "<p>Test Decrypt</p>";
	$decrypted = $bCrypt->decrypt( $encrypted );
	echo "<p>Payload: ".$decrypted."</p>";
	echo "<p>Faking Latency of 5s [curtime = ".time()."] [packet time = ".($encrypted["ts"] - 5 )." </p>";
	$encrypted["ts"] = ($encrypted["ts"] - 5 );
	pa( $encrypted );
	
	$decrypted = $bCrypt->decrypt( $encrypted );
	echo "<p>Payload: ".$decrypted."</p>";
	
	echo "<hr />";
	
	echo "<h1>With Tokens</h1>";
	$bCrypt->setEnableTokens();
	$encrypted = $bCrypt->encrypt( $msg );
	pa( $encrypted );
	
	echo "<p>Payload has Token ID: ".$encrypted["token"]."</p>";
	
	echo "<p>Testing Decrypt of Token</p>";
	
	$decrypted = $bCrypt->decrypt( $encrypted );
	
	echo "<p>Payload: ".$decrypted."</p>";
	
	echo "<p>Attempting <b>Second</b> Use of token.</p>";
	$decrypted = $bCrypt->decrypt( $encrypted );
	echo "<p>Payload: ".$decrypted."</p>";
	
	echo "<h1>With Public / Private Key</h1>";
	$bCrypt->setEnableKeys();
	$bCrypt->setPublicKey("test");
	$bCrypt->setPrivateKey("6b4f88c108845942fb344fc595e907a0");
	$encrypted = $bCrypt->encrypt( $msg );
	
	pa( $encrypted );
	
	echo "<p>Test Decrypt</p>";
	
	$decrypted = $bCrypt->decrypt( $encrypted );
	
	echo "<p>Payload: ".$decrypted."</p>";
	
	
	echo "<p>Test Decrypt with invalid private key</p>";
	$bCrypt->setPrivateKey("6b4f88c108845942fb344fc595e90invalida0");
	$encrypted = $bCrypt->encrypt( $msg );
	
	$decrypted = $bCrypt->decrypt( $encrypted );
	
	echo "<p>Payload: ".$decrypted."</p>";
?>