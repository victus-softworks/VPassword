## EXPERIMENTAL

_**IF YOU USE THIS IN PRODUCTION, YOU DO SO AT YOUR OWN RISK AND ARE PROBABLY VERY STUPID FOR DOING SO**_

This is an encryption/hashing library I wrote for a proprietary framework. This component is being open sourced for two reasons:

1. Auditability.
2. The public good, assuming 1 doesn't reveal hideous bugs.

DEPENDS ON https://github.com/DomBlack/php-scrypt

This requires that scrypt be enabled (`echo "extension=scrypt.so" >> /etc/php5/BLAHBLAH/php.ini` or whatever)

The process:

1. Calculate scrypt hash
2. Encrypt
    1. Derive auth and enc keys (eKey, aKey) from HKDF
    2. Encrypt with eKey (default: AES-CBC with PKCS#7 padding)
    3. Authenticate with HMAC, with aKey

### Threat Model

The benefit of a library is only present when your webserver and database are on separate hardware. Otherwise, you're just as well off using `scrypt` by itself.

If an attacker is able to compromise your database (e.g. through SQL Injection), this library should inhibit their ability to recover password hashes, since the hashes themselves are encrypted with a key only known to the webserver. This library does not help you in the event of a webserver compromise.

If an attacker is able to compromise your webserver, it's game over. Not only can they read hashes and decrypt them with the key, they can also modify your login scripts to log usernames and their associated plaintext passwords somewhere for later retrieval. This library does not help you in the event of a webserver compromise.

This library exists to make it more difficult to cross the gap between database compromise to offline password cracking, and does not make online attacking (e.g. guessing the top 10,000 most common passwords) difficult.
