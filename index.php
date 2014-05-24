<?php
/**
  Dependency: php-scrypt by domblack
  Dependency: mcrypt
*/
require_once "VSecure.php";
require_once "Scrypt.php";
require_once "VSymmetricCrypto.php";
require_once "VPassword.php";

$hash = VPassword::create("Your Password");
echo "{$hash}\n";
if(VPassword::verify($hash, "Your Password")) {
  echo "Success\n";
} else {
  echo "ERROR\n\n";
}

$some_other_key = VSecure::random(32);

$hash = VPassword::create("Your Password", $some_other_key);
echo "{$hash}\n";
if(VPassword::verify($hash, "Your Password", $some_other_key)) {
  echo "Success\n";
} else {
  echo "ERROR\n\n";
}
