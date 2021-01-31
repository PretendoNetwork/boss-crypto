const crypto = require('crypto');
const { md5, getDataFromPathOrBuffer } = require('./util');

const BOSS_CTR_VER = 0x10001;

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

	const hashType = data.readUInt16BE(0x18);

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
		throw new Error('Failed to decrypt. Missing content header magic');
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
	const programId = payloadContentHeader.subarray(0, 0x8); // this is the app title ID, the wiki calls it the "program ID"
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
		program_id: programId,
		content_datatype: contentDataType,
		ns_data_id: nsDataId,
		content
	};

	return container;
}

function encrypt3DS(pathOrBuffer, aesKey, options) {
	// Make sure all required options are passed
	if (!options.program_id && !options.title_id) {
		throw new Error('No program ID set. Set options.program_id or options.title_id');
	}

	if (!options.content_datatype) {
		throw new Error('No content datatype set. Set options.content_datatype');
	}

	if (!options.ns_data_id) {
		throw new Error('No NsDataId set. Set options.ns_data_id');
	}


	if (typeof aesKey === 'string') {
		aesKey = Buffer.from(aesKey, 'hex');
	}

	verifyKey(aesKey);

	const content = getDataFromPathOrBuffer(pathOrBuffer);

	let programId = options.program_id || options.title_id;
	const contentDataType = options.content_datatype;
	const nsDataId = options.ns_data_id;

	// dirty but it works without needing a 2nd temp variable
	if (typeof programId === 'string') {
		programId = parseInt(programId, 16);
	}

	if (typeof programId === 'number') {
		programId = BigInt(programId);
	}

	// Create payload content header
	let payloadContentHeader = Buffer.alloc(0x1C);

	payloadContentHeader.writeBigUInt64BE(programId);
	payloadContentHeader.writeUInt32BE(contentDataType, 0xC);
	payloadContentHeader.writeUInt32BE(content.length, 0x10);
	payloadContentHeader.writeUInt32BE(nsDataId, 0x14);
	payloadContentHeader.writeUInt32BE(1, 0x18); // Unknown

	const payloadContentHeaderHashedData = Buffer.concat([
		payloadContentHeader,
		Buffer.from('\x00\x00'),
		content
	]);
	const payloadContentHeaderHash = crypto.createHash('sha256').update(payloadContentHeaderHashedData).digest();

	payloadContentHeader = Buffer.concat([
		payloadContentHeader,
		payloadContentHeaderHash,
		Buffer.alloc(0x100) // zero-out RSA sign of the hash
	]);

	// Create the content header
	let contentHeader = Buffer.alloc(0x12);

	CONTENT_HEADER_MAGIC.copy(contentHeader, 0);
	contentHeader.writeUInt16BE(0x1, 0x10); // 3dbrew says "Used for generating the extdata filepath" but I'm not sure how it's used exactly

	const contentHeaderHashedData = Buffer.concat([
		contentHeader,
		Buffer.from('\x00\x00')
	]);
	const contentHeaderHash = crypto.createHash('sha256').update(contentHeaderHashedData).digest();

	contentHeader = Buffer.concat([
		contentHeader,
		contentHeaderHash,
		Buffer.alloc(0x100) // zero-out RSA sign of the hash
	]);

	// Create BOSS header
	const header = Buffer.alloc(0x28);

	header.write('boss', 0);
	header.writeUInt32BE(BOSS_CTR_VER, 0x4);
	// size of BOSS file skipped for now, will come back to it later
	header.writeBigUInt64BE(BigInt(Math.floor(new Date().getTime() / 1000)), 0xC);
	header.writeUInt16BE(1, 0x14);
	// 2 byte padding
	header.writeUInt16BE(2, 0x18);
	header.writeUInt16BE(2, 0x1A);
	// skipping CTR for now, will come back to it later

	// Crypto!
	const IV = crypto.randomBytes(12);

	const decrypted = Buffer.concat([
		contentHeader,
		payloadContentHeader,
		content
	]);

	const cipher = crypto.createCipheriv('aes-128-ctr', aesKey, Buffer.concat([IV, Buffer.from('\x00\x00\x00\x01')]));

	const encrypted = Buffer.concat([cipher.update(decrypted), cipher.final()]);

	// Fill the BOSS header in with the remaining parts
	header.writeUInt32BE(header.length + encrypted.length, 0x8);
	IV.copy(header, 0x1C);

	return Buffer.concat([
		header, encrypted
	]);
}

module.exports = {
	decrypt3DS,
	encrypt3DS
};