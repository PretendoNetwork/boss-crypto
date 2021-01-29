# boss.js
### Utility lib for working with BOSS/SpotPass data on the WiiU and (eventually) 3DS



## Installation
```
npm i https://github.com/PretendoNetwork/boss-js
```



## Supported functionality:
- [x] Decrypt (WiiU)
- [x] Encrypt (WiiU)
- [x] Decrypt (3DS) (no hashes or signatures are being verified due to lack of keys)
- [ ] Encrypt (3DS)



# Dumping crypto keys

## WiiU
BOSS/SpotPass uses 2 keys:
- AES encryption key
- HMAC key

We cannot provide these keys directly as they are owned by Nintendo. You must dump them yourself from your console in order to use this library

To dump keys needed see [this key dumping tool](https://github.com/PretendoNetwork/Full_Key_Dumper/)

## 3DS
Only one key is used to decrypt the contents, the AES encryption key. This is in keyslot 0x38. Other keys are used to check hashes and signatures but we don't have those so those checks are ignored. See [https://citra-emu.org/wiki/aes-keys/](https://citra-emu.org/wiki/aes-keys/) and [https://www.3dbrew.org/wiki/AES_Registers#Keyslots](https://www.3dbrew.org/wiki/AES_Registers#Keyslots) for more information


# Example
## Encrypting Splatoon Splatfest file
```js
const BOSS = require('boss-js');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THESE KEYS YOURSELF
const { BOSS_AES_KEY, BOSS_HMAC_KEY } = process.env;

const decryptedFilePath = __dirname + '/Festival.byml';

// Can also use BOSS.encrypt(decryptedFilePath, 0x20001, BOSS_AES_KEY, BOSS_HMAC_KEY);
const encrypted = BOSS.encryptWiiU(decryptedFilePath, BOSS_AES_KEY, BOSS_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.boss', encrypted);
```

## Decrypting Splatoon Splatfest file
```js
const BOSS = require('boss-js');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THESE KEYS YOURSELF
const { BOSS_AES_KEY, BOSS_HMAC_KEY } = process.env;

const encryptedFilePath = __dirname + '/Festival.boss';

const { content } = BOSS.decrypt(encryptedFilePath, BOSS_AES_KEY, BOSS_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.byml', content);
```

## Decrypting 3DS BGM file
```js
const BOSS = require('boss-js');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THIS KEY YOURSELF
const { BOSS_AES_KEY } = process.env;

const encryptedFilePath = __dirname + '/EU_BGM1.boss';

const container = BOSS.decrypt(encryptedFilePath, BOSS_AES_KEY);

fs.writeFileSync(__dirname + '/EU_BGM1.dec', container.content);
```



# API

## Container Object
This is just an object that contains all the relevant data for a BOSS/SpotPass file. It is NOT a real representation of the actual containers found in BOSS

```js
{
	release_date: <BigInt>, // Only on 3DS
	iv: <Buffer>,
	hash_type: <Number>,
	hmac: <Buffer>, // Only on WiiU
	content_header_hash: <Buffer>, // Only on 3DS
	content_header_hash_signature: <Buffer>, // Only on 3DS
	payload_content_header_hash: <Buffer>, // Only on 3DS
	payload_content_header_hash_signature: <Buffer>, // Only on 3DS
	program_id: <Buffer>, // Only on 3DS (title ID of the title)
	content_datatype: <Number>, // Only on 3DS
	ns_data_id: <Number>, // Only on 3DS
	content: <Buffer>
}
```

## `BOSS.decrypt(pathOrBuffer, aesKey, hmacKey);`

Takes in encrypted BOSS/SpotPass data and decrypts it. This function will check the BOSS header to see what version (WiiU or 3DS) the file is for and automatically call the corresponding decryption function

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
Container Object



## `BOSS.decryptWiiU(pathOrBuffer, aesKey, hmacKey);`

Takes in encrypted BOSS/SpotPass used for the WiiU data and decrypts it. This function is usually not needed and is called internally by `BOSS.decrypt`

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
Container Object



## `BOSS.encrypt(pathOrBuffer, version, aesKey, hmacKey);`

Takes in content and encrypts it. Will check `version` to know what version (WiiU or 3DS) the file is for and automatically call the corresponding encryption function

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `version`: BOSS/SpotPass version number (`0x10001` = 3DS, `0x20001` = WiiU)
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
Encrypted BOSS data depending on whatever version was set



## `BOSS.encryptWiiU(pathOrBuffer, aesKey, hmacKey);`

Takes in content and encrypts it for the WiiU

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
WiiU encrypted BOSS data



## `BOSS.decrypt3DS(pathOrBuffer, aesKey);`

Takes in content and encrypts it for the 3DS

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key

### Returns:
Container Object