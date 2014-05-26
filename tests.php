<?php
	require_once "BrenCrypt.php";
	function pa( $item ){
		echo "<pre>".print_r($item,true)."</pre>";
	}
	
	echo "<h1>Init Tests</h1>";
	echo "<h3>Simple Encryption</h3>";
	
	$bCrypt = new BrenCrypt();
	
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
	echo "<p>Faking Latency of 5s [curtime = ".time()."] [packet time = ".($encrypted["signed"] - 5 )." </p>";
	$encrypted["signed"] = ($encrypted["signed"] - 5 );
	pa( $encrypted );
	
	$decrypted = $bCrypt->decrypt( $encrypted );
	echo "<p>Payload: ".$decrypted."</p>";
	
	echo "<hr />";
	
	
	
	
?>