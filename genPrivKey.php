<?php
require_once "BrenCrypt.php";

if( isset($_REQUEST["key"]) && isset($_REQUEST["name"]) ){

	$publicKey = $_REQUEST["key"];
	$name = $_REQUEST["name"];

}

if( $publicKey == "" || $name == "" ){
	echo "Request String must have (public) 'key' and 'name' (for db lookup later) included";
	exit;
}

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
	


	$key = new BKeyin($conn);
	$key->setPubKey($publicKey);
	$key->setName($name);
	
	$privateKey = md5( $publicKey.$name.time() );
	$key->setPrivKey( $privateKey );
	
	if( $key->save() ){
		echo '<pre>'.print_r($key,true).'</pre>';
	
	}
	
	


?>