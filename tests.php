<?php
	require_once "BrenCrypt.php";
	
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


?>