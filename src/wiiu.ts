import crypto from 'node:crypto';
import { md5, getDataFromPathOrBuffer } from '@/util';

export type WUPBOSSInfo = {
	hash_type: number;
	iv: Buffer;
	hmac: Buffer;
	content: Buffer;
}

const BOSS_WUP_VER = 0x20001;

// * Not providing the keys
const BOSS_AES_KEY_HASH = Buffer.from('5202ce5099232c3d365e28379790a919', 'hex');
const BOSS_HMAC_KEY_HASH = Buffer.from('b4482fef177b0100090ce0dbeb8ce977', 'hex');

function verifyKeys(aesKey: string, hmacKey: string): void {
	if (!BOSS_AES_KEY_HASH.equals(md5(aesKey))) {
		throw new Error('Invalid BOSS AES key');
	}

	if (!BOSS_HMAC_KEY_HASH.equals(md5(hmacKey))) {
		throw new Error('Invalid BOSS HMAC key');
	}
}

export function decryptWiiU(pathOrBuffer: string | Buffer, aesKey: string, hmacKey: string): WUPBOSSInfo {
	verifyKeys(aesKey, hmacKey);

	const data = getDataFromPathOrBuffer(pathOrBuffer);

	const hashType = data.readUInt16BE(0xA);

	if (hashType !== 2) {
		throw new Error('Unknown hash type');
	}

	const IV = Buffer.concat([
		data.subarray(0xC, 0x18),
		Buffer.from('\x00\x00\x00\x01')
	]);

	const decipher = crypto.createDecipheriv('aes-128-ctr', aesKey, IV);

	const decrypted = Buffer.concat([decipher.update(data.subarray(0x20)), decipher.final()]);

	const hmac = decrypted.subarray(0, 0x20);
	const content = decrypted.subarray(0x20);

	const calculatedHmac = crypto.createHmac('sha256', hmacKey)
		.update(content)
		.digest();

	if (!calculatedHmac.equals(hmac)) {
		throw new Error('Content HMAC check failed');
	}

	return {
		hash_type: hashType,
		iv: IV,
		hmac,
		content
	};
}

export function encryptWiiU(pathOrBuffer: string | Buffer, aesKey: string, hmacKey: string): Buffer {
	verifyKeys(aesKey, hmacKey);

	const content = getDataFromPathOrBuffer(pathOrBuffer);

	const hmac = crypto.createHmac('sha256', hmacKey)
		.update(content)
		.digest();

	const decrypted = Buffer.concat([hmac, content]);

	const IV = process.env.NODE_ENV === 'test' ? Buffer.alloc(12) : crypto.randomBytes(12);

	const cipher = crypto.createCipheriv('aes-128-ctr', aesKey, Buffer.concat([IV, Buffer.from('\x00\x00\x00\x01')]));

	const encrypted = Buffer.concat([cipher.update(decrypted), cipher.final()]);

	const header = Buffer.alloc(0x20);

	header.write('boss', 0);
	header.writeUInt32BE(BOSS_WUP_VER, 0x4);
	header.writeUInt16BE(1, 0x8); // * Always 1
	header.writeUInt16BE(2, 0xA); // * Hash version

	IV.copy(header, 0xC);

	return Buffer.concat([
		header, encrypted
	]);
}