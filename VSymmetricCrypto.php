<?php

/**
 * Wrapper class for authenticated encryption with symmetric/shared keys
 */
abstract class VSymmetricCrypto {	
	// Message-signature separator
	const SEPARATOR = ':';
	
	// Ciphers
	const CIPHER_AES = 'AES';
	//const CIPHER_SALSA20 = 'Salsa20'; // SOMEDAY
	
	const BLOCK_MODE_CBC = 'CBC';
	const BLOCK_MODE_CTR = 'CTR';
	
	// Padding schemes:
	const PADDNG_NONE = 0;
	const PADDING_PKCS7 = 'PKCS7';
	
	const HASH_FUNC = 'sha256'; // For authentication
	
	/**
	 * Authenticate a message
	 * @param string $message
	 * @param string $aKey
	 */
	public static function authenticate($message, $aKey, $encode = true) {
		if($encode) {
			return base64_encode( hash_hmac(self::HASH_FUNC, $message, $aKey, true) );
		}
		return hash_hmac(self::HASH_FUNC, $message, $aKey, true);
	}
	
	/**
	 * Encrypt a message with a symmetric block cipher, then sign it with HMAC
	 * 
	 * @param string $plaintext
	 * @param blob $eKey
	 * @param blob $iv
	 * @param blob $aKey
	 * @param const $cipher
	 * @param const $block_mode
	 * @param const $padding
	 */
	public static function encrypt($plaintext, $eKey, $aKey, $iv = null,
		$cipher = self::CIPHER_AES, $block_mode = self::BLOCK_MODE_CBC,
		$padding = self::PADDING_PKCS7) {
		$message = self::encryptOnly($plaintext, $eKey, $iv, $cipher, $block_mode, $padding);
		return $message .self::SEPARATOR . self::authenticate($message, $aKey);
	}
	/**
	 * Encrypt a message with a symmetric block cipher
	 * 
	 * @param string $plaintext
	 * @param blob $eKey
	 * @param blob $iv
	 * @param const $cipher
	 * @param const $block_mode
	 * @param const $padding
	 */
	public static function encryptOnly($plaintext, $eKey, $iv = null,
		$cipher = self::CIPHER_AES, $block_mode = self::BLOCK_MODE_CBC,
		$padding = self::PADDING_PKCS7) {
		switch($cipher) {
			case self::CIPHER_AES:
				$block_size = 16;
				break;
			default:
				throw new VSecureException("Cipher not implemented!");
		}
		switch($padding) {
			case self::PADDING_PKCS7:
				$l = strlen($plaintext) % $block_size;
				$l = $block_size - $l;
				$plaintext .= str_repeat(chr($l), $l);
				break;
			case self::PADDNG_NONE:
				break;
		}
		if(empty($iv)) {
			
			$iv = VSecure::random($block_size);
		}
		switch($cipher) {
			case self::CIPHER_AES:
				return base64_encode($iv) .
					self::SEPARATOR .
					base64_encode( 
						mcrypt_encrypt(
							MCRYPT_RIJNDAEL_128, 
							$eKey,
							$plaintext,
							self::blockMode($block_mode),
							$iv
						)
					);
		}
		// Still here? Sigh...
		throw new VSecureException("Cipher not implemented!");
	}
	/**
	 * Decryption -- note that there is no IV value; it should be prefixed to the
	 * plaintext
	 * @param string $ciphertext
	 * @param string $eKey
	 * @param string $aKey
	 * @param string $cipher
	 * @param string $block_mode
	 * @param string $padding
	 */
	public static function decrypt($ciphertext, $eKey, $aKey,
		$cipher = self::CIPHER_AES, $block_mode = self::BLOCK_MODE_CBC,
		$padding = self::PADDING_PKCS7) {
		if(self::verify( $ciphertext, $aKey )) {
			return self::decryptOnly($ciphertext, $eKey, $cipher, $block_mode, $padding);
		} else {
			throw new VSecureException("Signature did not match!");
		}
		
	}
	/**
	 * Decryption without signature verification
	 * 
	 * @param string $ciphertext
	 * @param string $eKey
	 * @param string $cipher
	 * @param string $block_mode
	 * @param string $padding
	 */
	public static function decryptOnly($ciphertext, $eKey,
		$cipher = self::CIPHER_AES, $block_mode = self::BLOCK_MODE_CBC,
		$padding = self::PADDING_PKCS7) {
		list($iv, $message) = explode(self::SEPARATOR, $ciphertext);
		
		switch($cipher) {
			case self::CIPHER_AES:
				$plain = mcrypt_decrypt(
						MCRYPT_RIJNDAEL_128,
						$eKey,
						base64_decode($message),
						self::blockMode($block_mode),
						base64_decode($iv)
					);
				break;
			default:
				throw new VSecureException("Cipher not implemented!");
		}
		switch($padding) {
			case self::PADDING_PKCS7:
				$l = strlen($plain) - ord($plain[strlen($plain) - 1]);
				return substr($plain, 0, $l);
			default:
				return $plain;
		}
	}
	/**
	 * Get the raw underlying mode (currently mcrypt, can be swapped out later)
	 * @param const $mode
	 * @return library const
	 */
	public static function blockMode($mode = self::BLOCK_MODE_CBC) {
		switch($mode) {
			case self::BLOCK_MODE_CBC:
				if(defined('MCRYPT_MODE_CBC')) {
					return MCRYPT_MODE_CBC;
				} else {
					throw new VSecureException("Mcrypt not enabled!");
				}
			case self::BLOCK_MODE_CTR:
				return 'ctr';
		}
	}
	/**
	 * Verify the signature on an encrypted message
	 * @param string $ciphertext
	 * @param string $aKey
	 * @param string $sig
	 */
	public static function verify($ciphertext, $aKey, $sig = null) {
		if(!empty($sig)) {
			throw new VSecureException("Anti-pattern detected. GTFO");
		} else {
			list($iv, $cipher, $sig) = explode(self::SEPARATOR, $ciphertext);
		}
		$calc = self::authenticate($iv . self::SEPARATOR . $cipher, $aKey);
		return VSecure::compare($calc, $sig);
	}
}
