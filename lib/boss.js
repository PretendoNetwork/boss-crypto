const fs = require('fs');
const crypto = require('crypto');

const BOSS_MAGIC = Buffer.from('boss');
const BOSS_CTR_VER = 0x10001;
const BOSS_WUP_VER = 0x20001;

// Not providing the keys
const BOSS_AES_KEY_HASH = Buffer.from('5202ce5099232c3d365e28379790a919', 'hex');
const BOSS_HMAC_KEY_HASH = Buffer.from('b4482fef177b0100090ce0dbeb8ce977', 'hex');

function encrypt(pathOrBuffer, version, aesKey, hmacKey) {
	verifyKeys(aesKey, hmacKey);

	const data = getDataFromPathOrBuffer(pathOrBuffer);

	if (version === BOSS_WUP_VER) {
		return encryptWiiU(data, aesKey, hmacKey);
	} else if (version === BOSS_CTR_VER) {
		throw new Error('CTR SpotPass data not supported yet');
	} else {
		throw new Error('Unknown version');
	}
}

function decrypt(pathOrBuffer, aesKey, hmacKey) {
	verifyKeys(aesKey, hmacKey);

	const data = getDataFromPathOrBuffer(pathOrBuffer);

	const magic = data.subarray(0, 0x4);

	if (!magic.equals(BOSS_MAGIC)) {
		throw new Error('Missing boss magic');
	}

	const version = data.readUInt32BE(4);

	if (version === BOSS_WUP_VER) {
		return decryptWiiU(data, aesKey, hmacKey);
	} else if (version === BOSS_CTR_VER) {
		throw new Error('CTR SpotPass data not supported yet');
	} else {
		throw new Error('Unknown header version');
	}
}

function decryptWiiU(pathOrBuffer, aesKey, hmacKey) {
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
	
	return content;
}

function encryptWiiU(pathOrBuffer, aesKey, hmacKey) {
	verifyKeys(aesKey, hmacKey);

	const content = getDataFromPathOrBuffer(pathOrBuffer);

	const hmac = crypto.createHmac('sha256', hmacKey)
		.update(content)
		.digest();

	const decrypted = Buffer.concat([hmac, content]);

	const IV = crypto.randomBytes(12);

	const cipher = crypto.createCipheriv('aes-128-ctr', aesKey, Buffer.concat([IV, Buffer.from('\x00\x00\x00\x01')]));

	const encrypted = Buffer.concat([cipher.update(decrypted), cipher.final()]);

	const header = Buffer.alloc(0x20);

	header.write('boss', 0);
	header.writeUInt32BE(BOSS_WUP_VER, 0x4);
	header.writeUInt16BE(1, 0x8); // always 1
	header.writeUInt16BE(2, 0xA); // hash version
	header.write(IV.toString('hex'), 0xC, 'hex');
	
	return Buffer.concat([
		header, encrypted
	]);
}

function md5(input) {
	return crypto.createHash('md5').update(input).digest();
}

function verifyKeys(aesKey, hmacKey) {
	if (!BOSS_AES_KEY_HASH.equals(md5(aesKey))) {
		throw new Error('Invalid BOSS AES key');
	}

	if (!BOSS_HMAC_KEY_HASH.equals(md5(hmacKey))) {
		throw new Error('Invalid BOSS HMAC key');
	}
}

function getDataFromPathOrBuffer(pathOrBuffer) {
	let data;
	if (pathOrBuffer instanceof Buffer) {
		data = pathOrBuffer;
	} else {
		data = fs.readFileSync(pathOrBuffer);
	}

	return data;
}

module.exports = {
	encrypt, decrypt,
	decryptWiiU, encryptWiiU
};