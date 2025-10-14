# boss-crypto
### TypeScript crypto functions for creating and working with WiiU and 3DS BOSS (SpotPass) files

## Installation
```
npm i @pretendonetwork/boss-crypto
```

## Supported functionality:
- [x] Decrypt (WiiU)
- [x] Encrypt (WiiU)
- [x] Decrypt (3DS) (RSA hash signatures are not verified due to lack of public key)
- [x] Encrypt (3DS)

# Dumping crypto keys

## WiiU
BOSS uses 2 keys:
- AES encryption key
- HMAC key

We cannot provide these keys directly as they are owned by Nintendo. You must dump them yourself from your console in order to use this library

To dump keys needed see [this key dumping tool](https://github.com/PretendoNetwork/BetterKeyDumper)

## 3DS
Only one key is used to decrypt the contents, the AES encryption key. This is in keyslot 0x38 (Normalkey). See [https://citra-emu.org/wiki/aes-keys/](https://citra-emu.org/wiki/aes-keys/) and [https://www.3dbrew.org/wiki/AES_Registers#Keyslots](https://www.3dbrew.org/wiki/AES_Registers#Keyslots) for more information. The SHA256 hashes are RSA signed, however we lack both the private and public key. So we cannot sign our own hashes legitimately and we cannot verify legitimate hashes. Luckily Luma patches these signature checks anyway


# Usage
## Encryption WiiU
```ts
import fs from 'node:fs';
import { encryptWiiU } from '@pretendonetwork/boss-crypto';

const { BOSS_AES_KEY, BOSS_HMAC_KEY } = process.env;

const content = Buffer.from('Hello World');
const encrypted = encryptWiiU(content, BOSS_WIIU_AES_KEY, BOSS_WIIU_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.boss', encrypted);
```

## Decryption WiiU
```ts
import fs from 'node:fs';
import { decryptWiiU } from '@pretendonetwork/boss-crypto';

const { BOSS_AES_KEY, BOSS_HMAC_KEY } = process.env;

const encryptedFilePath = __dirname + '/Festival.boss';

const { content } = decryptWiiU(encryptedFilePath, BOSS_AES_KEY, BOSS_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.byml', content);
```

## Encryption 3DS
```ts
import fs from 'node:fs';
import { encrypt3DS } from '@pretendonetwork/boss-crypto';

const { BOSS_AES_KEY } = process.env;

const content = Buffer.from('Hello World');
const encrypted = encrypt3DS(BOSS_3DS_AES_KEY, 1692231927n, {
	program_id: 0x0004001000022900, // can also be named "title_id"
	content_datatype: 65537,
	ns_data_id: 36,
	version: 1,
	content,
});

fs.writeFileSync(__dirname + '/hello-world.boss', encrypted);
```

## Decryption 3DS
```ts
import fs from 'node:fs';
import { decrypt3DS } from '@pretendonetwork/boss-crypto';

const { BOSS_AES_KEY } = process.env;

const encryptedFilePath = __dirname + '/EU_BGM1';

const { payload_contents } = decrypt3DS(encryptedFilePath, BOSS_AES_KEY);

fs.writeFileSync(__dirname + '/EU_BGM1.dec', payload_contents[0].content);
```

# API

## Types

### WUPBOSSInfo
Returned when decrypting WiiU BOSS content. Contains some crypto information from the headers

_**THIS TYPE IS <ins>NOT</ins> PART OF THE REAL BOSS SPEC. IT IS MADE FOR THIS LIBRARY ONLY**_

```ts
type WUPBOSSInfo = {
	hash_type: number;
	iv: Buffer;
	hmac: Buffer;
	content: Buffer;
}
```

### CTRBOSSFlag
Holds flags representing additional information of a 3DS BOSS container

- `CTR_BOSS_FLAGS.MARK_ARRIVED_PRIVILEGED`: If set, the titles which are targeted in the payload contents will only be notified of the arrival of new data if they are privileged titles. For example, this is used by regular titles downloading notification tasks which aren't targeted to the title itself, but to the notifications sysmodule

### CTRPayloadContent
Holds the contents of one of the payloads of a 3DS BOSS container

```ts
type CTRPayloadContent = {
	payload_content_header_hash: Buffer;
	payload_content_header_hash_signature: Buffer;
	program_id: bigint;
	content_datatype: number;
	ns_data_id: number;
	version: number;
	content: Buffer;
}
```

### CTRBOSSContainer
Returned when decrypting 3DS BOSS content. Contains all relevant data from the real BOSS container. See https://www.3dbrew.org/wiki/SpotPass#Content_Container for more details

```ts
type CTRBOSSContainer = {
	hash_type: number;
	serial_number: bigint;
	iv: Buffer;
	flags: CTRBOSSFlag;
	content_header_hash: Buffer;
	content_header_hash_signature: Buffer;
	payload_contents: CTRPayloadContent[];
}
```

### CTRCryptoOptions
Passed in when encrypting 3DS contents. `program_id` and `title_id` are aliases, one must be set. `serial_number` and `flags` are only needed when calling `encrypt`. `content` is only needed when calling `encrypt3DS`

```ts
type CTRCryptoOptions = {
	program_id?: string | number | bigint;
	title_id?: string | number | bigint;
	serial_number?: bigint;
	flags?: CTRBOSSFlag;
	content_datatype: number;
	ns_data_id: number;
	version: number;
	content?: string | Buffer;
}
```

## Methods

## decrypt

### Signature
```ts
function decrypt(pathOrBuffer: string | Buffer, aesKey: string, hmacKey?: string): WUPBOSSInfo | CTRBOSSContainer
```

Takes in encrypted BOSS data and decrypts it. This function will check the BOSS header to see what version (WiiU or 3DS) the file is for and automatically call the corresponding decryption function

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: AES encryption key
- `hmacKey`: HMAC key (WiiU only)

### Returns:
`WUPBOSSInfo | CTRBOSSContainer`

## encrypt

### Signature
```ts
function encrypt(pathOrBuffer: string | Buffer, version: number, aesKey: string, hmacKeyOrOptions: string | CTRCryptoOptions): Buffer
```

Takes in content and encrypts it. Will check `version` to know what version (WiiU or 3DS) the file is for and automatically call the corresponding encryption function

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `version`: BOSS version number (`0x10001` = 3DS, `0x20001` = WiiU)
- `aesKey`: BOSS AES encryption key
- `hmacKeyOrOptions`: BOSS HMAC key (WiiU) or `CTRCryptoOptions` (3DS)

### Returns:
Encrypted BOSS data buffer

## decryptWiiU

### Signature
```ts
function decryptWiiU(pathOrBuffer: string | Buffer, aesKey: string, hmacKey: string): WUPBOSSInfo
```

Takes in encrypted BOSS used for the WiiU data and decrypts it. This function is usually not needed and is called internally by `decrypt`

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS AES encryption key
- `hmacKey`: BOSS HMAC key

### Returns:
`WUPBOSSInfo`

## encryptWiiU

### Signature
```ts
function encryptWiiU(pathOrBuffer: string | Buffer, aesKey: string, hmacKey: string): Buffer
```

Takes in content and encrypts it for the WiiU

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS AES encryption key
- `hmacKey`: BOSS HMAC key

### Returns:
WiiU encrypted BOSS data

## decrypt3DS

### Signature
```ts
function decrypt3DS(pathOrBuffer: string | Buffer, aesKey: string | Buffer): CTRBOSSContainer
```

Takes in encrypted BOSS used for the 3DS data and decrypts it. This function is usually not needed and is called internally by `decrypt`

### Arguments
- `pathOrBuffer`: Either a string path to the file or a buffer containing the raw data
- `aesKey`: BOSS AES encryption key

### Returns:
`CTRBOSSContainer`

## encrypt3DS

### Signature
```ts
function encrypt3DS(aesKey: string | Buffer, serialNumber: bigint, options: CTRCryptoOptions[], flags?: CTRBOSSFlag): Buffer
```

Takes in multiple contents and encrypts them for the 3DS using the provided options and serial number

### Arguments
- `aesKey`: BOSS AES encryption key
- `serialNumber`: Serial number used in the BOSS container. This is a unique identifier of the container, similar to the data ID on the Wii U (not to be confused with the NS Data ID, which is assigned per payload content)
- `options`: Array of `CTRCryptoOptions`
- `flags`: Container flags `CTRBOSSFlag`

### Returns:
3DS encrypted BOSS data
