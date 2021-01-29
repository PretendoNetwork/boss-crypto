const { getDataFromPathOrBuffer } = require('./util');
const { decryptWiiU, encryptWiiU } = require('./wiiu');
const { decrypt3DS } = require('./3ds');

const BOSS_MAGIC = Buffer.from('boss');
const BOSS_CTR_VER = 0x10001;
const BOSS_WUP_VER = 0x20001;

function encrypt(pathOrBuffer, version, aesKey, hmacKey) {
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
	const data = getDataFromPathOrBuffer(pathOrBuffer);

	const magic = data.subarray(0, 0x4);

	if (!magic.equals(BOSS_MAGIC)) {
		throw new Error('Missing boss magic');
	}

	const version = data.readUInt32BE(4);

	if (version === BOSS_WUP_VER) {
		return decryptWiiU(data, aesKey, hmacKey);
	} else if (version === BOSS_CTR_VER) {
		return decrypt3DS(data, aesKey);
	} else {
		throw new Error('Unknown header version');
	}
}

module.exports = {
	encrypt, decrypt,
	decryptWiiU, encryptWiiU,
	decrypt3DS
};