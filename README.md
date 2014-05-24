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
