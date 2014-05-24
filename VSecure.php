<?php
class VSecureException extends Exception {}

class VSecure {
	/* SNIP OUT STUFF (HTMLPURIFIER INTERFACE, ETC) THAT'S NOT AT ALL RELATED TO THE OPERATIONS HERE */

	/**
	 * Safe comparison function
	 * Adopted from the Scrypt comparison method
	 * 
	 * @param string $expected
	 * @param string $actual
	 * @return boolean
	 */
	public static function compare($expected, $actual) {
		if(version_compare( phpversion(), '5.6.0', '>=' )) {
			// Use the native C implementation that ships with PHP instead
			return hash_compare($expected, $actual);
		}
		$expected = (string) $expected;
		$actual = (string) $actual;
		$lenExpected = strlen($expected);
		$lenActual = strlen($actual);
		$len = min($lenExpected, $lenActual);
		$result = 0;
		for($i = 0; $i < $len; ++$i) {
			$result |= ord($expected[$i]) ^ ord($actual[$i]);
		}
		$result |= $lenExpected ^ $lenActual;
		return ($result === 0);
	}

	/**
	 * HMAC-based Key Derivation Function
	 * http://tools.ietf.org/html/rfc5869
	 * 
	 * Use this to derive sub-keys from a master key
	 * (e.g. one separate for encryption and authentication)
	 * 
	 * Adopted from CodeIgniter's new Encryption class
	 * 
	 * @param blob $key
	 * @param blob $salt
	 * @param string $purpose
	 * @param string $digest
	 * @param int $length
	 * @return type
	 * @throws VSecureException
	 */
	public static function hkdf($key, $salt = NULL, $purpose = '', $digest = 'sha256', $length = NULL) {
		if(empty($length)) {
			switch($digest) {
				case 'sha256':
					$length = 32;
					break;
				default:
					throw new VSecureException("HKDF Digest not supported");
			}
		}
		strlen($salt) OR $salt = str_repeat("\0", $length);
		$prk = hash_hmac($digest, $key, $salt, TRUE);
		$key = '';
		for($key_block = '', $block_index = 1; strlen($key) < $length; ++$block_index) {
			$key_block = hash_hmac($digest, $key_block.$purpose.chr($block_index), $prk, TRUE);
			$key .= $key_block;
		}
		return substr($key, 0, $length);
	}
	public static function random($block_size) {
		if(is_readable('/dev/urandom')) {
			$fp = fopen('/dev/urandom', 'rb');
			$buff = fread($fp, $block_size);
			fclose($fp);
			return $buff;
		} elseif(function_exists('mcrypt_create_iv')) {
			return mcrypt_create_iv($block_size, MCRYPT_DEV_URANDOM);
		} elseif(function_exists('openssl_random_pseudo_bytes')) {
			// What the hell are we doing here? Mcrypt is needed for encryption...
			return openssl_random_pseudo_bytes($block_size);
		} 
		throw new VSecureException("No suitable CSPRNG available!");
	}
}
