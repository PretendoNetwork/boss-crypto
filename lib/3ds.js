const crypto = require('crypto');
const { md5, getDataFromPathOrBuffer } = require('./util');

//const BOSS_CTR_VER = 0x10001; // for use later when we generate files

// Not providing the key
const BOSS_AES_KEY_HASH = Buffer.from('86fbc2bb4cb703b2a4c6cc9961319926', 'hex');

const CONTENT_HEADER_MAGIC = Buffer.from('80000000000000000000000000000000', 'hex');


function verifyKey(aesKey) {
	if (!BOSS_AES_KEY_HASH.equals(md5(aesKey))) {
		throw new Error('Invalid BOSS AES key');
	}
}

function decrypt3DS(pathOrBuffer, aesKey) {
	if (typeof aesKey === 'string') {
		aesKey = Buffer.from(aesKey, 'hex');
	}

	verifyKey(aesKey);

	const data = getDataFromPathOrBuffer(pathOrBuffer);

	//////////////////////////////////////////////////////////////////////
	// BOSS header for 3DS according to 3dbrew. Skipping unneeded parts //
	// 0x0	0x4	Magic Number "boss"                                     //
	// 0x4	0x4	Magic Number 0x10001                                    //
	// 0x8	0x4	Big-endian filesize                                     //
	// 0xC	0x8	u64 release date (UNIX timestamp)                       //
	// 0x14	0x2	Must always be 0x1                                      //
	// 0x16	0x2	Padding                                                 //
	// 0x18	0x2	Content header hash type, always 0x2 for SHA-256        //
	// 0x1A	0x2	Content header RSA size, always 0x2 for RSA-2048 (X<<7) //
	// 0x1C	0xC	First 12 bytes of the CTR                               //
	//////////////////////////////////////////////////////////////////////

	const IV = Buffer.concat([
		data.subarray(0x1C, 0x28),
		Buffer.from('\x00\x00\x00\x01')
	]);

	const decipher = crypto.createDecipheriv('aes-128-ctr', aesKey, IV);

	const decryptedContent = Buffer.concat([decipher.update(data.subarray(0x28)), decipher.final()]);

	const decryptedContentHeader = decryptedContent.subarray(0, 0x132);

	if (!CONTENT_HEADER_MAGIC.equals(decryptedContentHeader.subarray(0, 0x10))) {
		throw new Error('Failed to decrypt');
	}

	// Skip the rest of the content header since we don't have the keys to check any of it

	const payloadContentHeader = decryptedContent.subarray(0x132, 0x26E);
	const contentLength = payloadContentHeader.readUInt32BE(0x10);

	// Need to find the other keys to verfy this stuff in the header

	const content = decryptedContent.subarray(0x26E);

	if (contentLength !== content.length) {
		throw new Error('Content length does not match header');
	}

	return content;
}

module.exports = {
	decrypt3DS
};