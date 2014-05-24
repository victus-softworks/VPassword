<?php
/**
 * Victus Softworks
 * Based on the work of Dominic Black
 * VPassword -- wraps scrypt inside of a block cipher
 */
abstract class VPassword {
	const DEFAULT_KEY = 'aewOQ/92irn1Dd80aoLM2h8/Rn8rLwXAhQWnw/gPi1M=';
	/**
	 * Hash a password with scrypt then encrypt it with a symmetric encryption key
	 * 
	 * @global type $Victus
	 * @param string $string
	 * @param string $_key (optional)
	 * @return type
	 */
	public static function create($string, $_key = null) {
		list($eKey, $aKey) = self::getKeys($_key);
		return VSymmetricCrypto::encrypt(
			Scrypt::hash($string), $eKey, $aKey
		);
	}
	/**
	 * Decrypt then verify the hash
	 * 
	 * @param string $cipher
	 * @param string $plain
	 * @param string $_key (optional)
	 */
	public static function verify($cipher, $plain, $_key = null) {
		list($eKey, $aKey) = self::getKeys($_key);
		$hash = VSymmetricCrypto::decrypt($cipher, $eKey, $aKey);
		return Scrypt::check($plain, $hash);
	}
	/**
	 * Return an encryption and authentication key
	 * @param blob $_key
	 */
	public static function getKeys($_key = null) {
		if(empty($_key)) {
			// Default password key is stored as a base64-encoded value
			$_key = base64_decode(self::DEFAULT_KEY);
		}
		return [
			VSecure::hkdf($_key, 'password keygen.', 'encryption'),
			VSecure::hkdf($_key, 'password keygen.', 'authentication')
		];
	}
}
