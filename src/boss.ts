import { getDataFromPathOrBuffer } from '@/util';
import { decryptWiiU, encryptWiiU, WUPBOSSInfo } from '@/wiiu';
import { decrypt3DS, encrypt3DS, CTRBOSSContainer, CTRCryptoOptions } from '@/3ds';

const BOSS_MAGIC = Buffer.from('boss');
const BOSS_CTR_VER = 0x10001;
const BOSS_WUP_VER = 0x20001;

export { decryptWiiU as decryptWiiU };
export { encryptWiiU as encryptWiiU };
export { decrypt3DS as decrypt3DS };
export { encrypt3DS as encrypt3DS };

export function encrypt(pathOrBuffer: string | Buffer, version: number, aesKey: string, hmacKeyOrOptions: string | CTRCryptoOptions): Buffer {
	const data = getDataFromPathOrBuffer(pathOrBuffer);

	if (version === BOSS_WUP_VER) {
		if (typeof hmacKeyOrOptions !== 'string') {
			throw new Error('Invalid WiiU HMAC key');
		}

		return encryptWiiU(data, aesKey, hmacKeyOrOptions);
	} else if (version === BOSS_CTR_VER) {
		if (typeof hmacKeyOrOptions === 'string') {
			throw new Error('Invalid CTRCryptoOptions');
		}

		if (typeof hmacKeyOrOptions.serial_number === 'undefined') {
			throw new Error('Serial number is undefined');
		}

		hmacKeyOrOptions.content = data;
		return encrypt3DS(aesKey, hmacKeyOrOptions.serial_number, [hmacKeyOrOptions], hmacKeyOrOptions.flags);
	} else {
		throw new Error('Unknown version');
	}
}

export function decrypt(pathOrBuffer: string | Buffer, aesKey: string, hmacKey?: string): WUPBOSSInfo | CTRBOSSContainer {
	const data = getDataFromPathOrBuffer(pathOrBuffer);

	const magic = data.subarray(0, 0x4);

	if (!magic.equals(BOSS_MAGIC)) {
		throw new Error('Missing boss magic');
	}

	const version = data.readUInt32BE(4);

	if (version === BOSS_WUP_VER) {
		if (!hmacKey) {
			throw new Error('WiiU crypto requires an hmac key');
		}

		return decryptWiiU(data, aesKey, hmacKey);
	} else if (version === BOSS_CTR_VER) {
		return decrypt3DS(data, aesKey);
	} else {
		throw new Error('Unknown header version');
	}
}
