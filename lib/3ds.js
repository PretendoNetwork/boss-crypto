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

	// PARSE THE BOSS DATA HEADER
	const data = getDataFromPathOrBuffer(pathOrBuffer);

	const hashType = data.readUInt16BE(0xA);

	if (hashType !== 2) {
		throw new Error('Unknown hash type');
	}

	const releaseDate = data.readBigUInt64BE(0xC);

	const IV = Buffer.concat([
		data.subarray(0x1C, 0x28),
		Buffer.from('\x00\x00\x00\x01')
	]);

	// DECRYPT BOSS CONTENT
	const decipher = crypto.createDecipheriv('aes-128-ctr', aesKey, IV);

	const decryptedContent = Buffer.concat([decipher.update(data.subarray(0x28)), decipher.final()]);

	// PARSE CONTENT HEADER
	const contentHeader = decryptedContent.subarray(0, 0x132);
	const contentHeaderMagic = contentHeader.subarray(0, 0x10);

	if (!contentHeaderMagic.equals(CONTENT_HEADER_MAGIC)) {
		throw new Error('Failed to decrypt');
	}

	const contentHeaderHash = contentHeader.subarray(0x12, 0x32);
	const contentHeaderHashSignature = contentHeader.subarray(0x32, 0x132);

	const contentHeaderHashedData = Buffer.concat([
		contentHeader.subarray(0, 0x12),
		Buffer.from('\x00\x00')
	]);
	const calculatedContentHeaderHash = crypto.createHash('sha256').update(contentHeaderHashedData).digest();
	
	if (!calculatedContentHeaderHash.equals(contentHeaderHash)) {
		throw new Error('Content header SHA256 hash did not match');
	}

	// PARSE THE PAYLOAD CONTENT HEADER
	const payloadContentHeader = decryptedContent.subarray(0x132, 0x26E);
	const programID = payloadContentHeader.subarray(0, 0x8); // this is the app title ID, the wiki calls it the "program ID"
	const contentDataType = payloadContentHeader.readUInt32BE(0xC);
	const contentLength = payloadContentHeader.readUInt32BE(0x10);
	const nsDataId = payloadContentHeader.readUInt32BE(0x14);
	const payloadContentHeaderHash = payloadContentHeader.subarray(0x1C, 0x3C);
	const payloadContentHeaderHashSignature = payloadContentHeader.subarray(0x3C, 0x13C);

	const content = decryptedContent.subarray(0x26E);

	const payloadContentHeaderHashedData = Buffer.concat([
		payloadContentHeader.subarray(0, 0x1C),
		Buffer.from('\x00\x00'),
		content
	]);
	const calculatedPayloadContentHeaderHash = crypto.createHash('sha256').update(payloadContentHeaderHashedData).digest();

	if (!calculatedPayloadContentHeaderHash.equals(payloadContentHeaderHash)) {
		throw new Error('Payload content header SHA256 hash did not match');
	}

	if (contentLength !== content.length) {
		throw new Error('Content length does not match header');
	}

	// We don't do any RSA signature verification because we don't have the public key

	const container = {
		hash_type: hashType,
		release_date: releaseDate,
		iv: IV,
		content_header_hash: contentHeaderHash,
		content_header_hash_signature: contentHeaderHashSignature,
		payload_content_header_hash: payloadContentHeaderHash,
		payload_content_header_hash_signature: payloadContentHeaderHashSignature,
		program_id: programID,
		content_datatype: contentDataType,
		ns_data_id: nsDataId,
		content
	};

	return container;
}

module.exports = {
	decrypt3DS
};