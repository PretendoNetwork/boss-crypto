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
BOSS/SpotPass uses 2 keys:
- AES encryption key
- HMAC key

We cannot provide these keys directly as they are owned by Nintendo. You must dump them yourself from your console in order to use this library

To dump keys needed see [this key dumping tool](https://github.com/PretendoNetwork/Full_Key_Dumper/)



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

const decrypted = BOSS.decrypt(encryptedFilePath, BOSS_AES_KEY, BOSS_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.byml', decrypted);
```



# API

## `BOSS.decrypt(pathOrBuffer, aesKey, hmacKey);`

Takes in encrypted BOSS/SpotPass data and decrypts it. This function will check the BOSS header to see what version (WiiU or 3DS) the file is for and automatically call the corresponding decryption function

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
Decrypted content body



## `BOSS.decryptWiiU(pathOrBuffer, aesKey, hmacKey);`

Takes in encrypted BOSS/SpotPass used for the WiiU data and decrypts it. This function is usually not needed and is called internally by `BOSS.decrypt`

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
Decrypted content body



## `BOSS.encrypt(pathOrBuffer, version, aesKey, hmacKey);`

Takes in content and encrypts it. Will check `version` to know what version (WiiU or 3DS) the file is for and automatically call the corresponding encryption function

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `version`: BOSS/SpotPass version number (`0x10001` = 3DS, `0x20001` = WiiU)
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
Encrypted BOSS data



## `BOSS.encryptWiiU(pathOrBuffer, aesKey, hmacKey);`

Takes in content and encrypts it for the WiiU

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS/SpotPass AES encryption key
- `hmacKey`: BOSS/SpotPass HMAC key

### Returns:
WiiU encrypted BOSS data