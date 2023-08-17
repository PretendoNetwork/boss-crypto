import crypto from 'node:crypto';
import { md5, getDataFromPathOrBuffer } from '@/util';

export type CTRBOSSContainer = {
	hash_type: number;
	release_date: bigint;
	iv: Buffer;
	content_header_hash: Buffer;
	content_header_hash_signature: Buffer;
	payload_content_header_hash: Buffer;
	payload_content_header_hash_signature: Buffer;
	program_id: bigint;
	content_datatype: number;
	ns_data_id: number;
	content: Buffer;
}

export type CTRCryptoOptions = {
	program_id?: string | number | bigint; // * Program ID and title ID are aliases
	title_id?: string | number | bigint;   // * Program ID and title ID are aliases
	release_date: bigint;
	content_datatype: number;
	ns_data_id: number;
}

const BOSS_CTR_VER = 0x10001;

// Not providing the key
const BOSS_AES_KEY_HASH = Buffer.from('86fbc2bb4cb703b2a4c6cc9961319926', 'hex');

const CONTENT_HEADER_MAGIC = Buffer.from('80000000000000000000000000000000', 'hex');

function verifyKey(aesKey: Buffer): void {
	if (!BOSS_AES_KEY_HASH.equals(md5(aesKey))) {
		throw new Error('Invalid BOSS AES key');
	}
}

export function decrypt3DS(pathOrBuffer: string | Buffer, aesKey: string | Buffer): CTRBOSSContainer {
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
		console.log(contentHeaderMagic.toString('hex'));
		//throw new Error('Failed to decrypt. Missing content header magic');
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

	// * PARSE THE PAYLOAD CONTENT HEADER
	const payloadContentHeader = decryptedContent.subarray(0x132, 0x26E);
	const programID = payloadContentHeader.readBigUInt64LE(); // * This is the app title ID, the wiki calls it the "program ID"
	const contentDataType = payloadContentHeader.readUInt32BE(0xC);
	const contentLength = payloadContentHeader.readUInt32BE(0x10);
	const nsDataID = payloadContentHeader.readUInt32BE(0x14);
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

	// * We don't do any RSA signature verification because we don't have the public key

	return {
		hash_type: hashType,
		release_date: releaseDate,
		iv: IV,
		content_header_hash: contentHeaderHash,
		content_header_hash_signature: contentHeaderHashSignature,
		payload_content_header_hash: payloadContentHeaderHash,
		payload_content_header_hash_signature: payloadContentHeaderHashSignature,
		program_id: programID,
		content_datatype: contentDataType,
		ns_data_id: nsDataID,
		content
	};
}

export function encrypt3DS(pathOrBuffer: string | Buffer, aesKey: string | Buffer, options: CTRCryptoOptions): Buffer {
	if (typeof aesKey === 'string') {
		aesKey = Buffer.from(aesKey, 'hex');
	}

	verifyKey(aesKey);

	const content = getDataFromPathOrBuffer(pathOrBuffer);

	let programID: string | number | bigint;

	if (options.program_id) {
		programID = options.program_id;
	} else if (options.title_id) {
		programID = options.title_id;
	} else {
		throw new Error('No program ID set. Set options.program_id or options.title_id');
	}

	if (typeof programID === 'string') {
		programID = BigInt(parseInt(programID, 16));
	}

	if (typeof programID === 'number') {
		programID = BigInt(programID);
	}

	let contentHeader = Buffer.alloc(0x12);

	CONTENT_HEADER_MAGIC.copy(contentHeader, 0);
	contentHeader.writeUInt16BE(0x1, 0x10); // * 3dbrew says "Used for generating the extdata filepath" but I'm not sure how it's used exactly

	const contentHeaderHashedData = Buffer.concat([
		contentHeader,
		Buffer.from('\x00\x00')
	]);
	const contentHeaderHash = crypto.createHash('sha256').update(contentHeaderHashedData).digest();

	contentHeader = Buffer.concat([
		contentHeader,
		contentHeaderHash,
		Buffer.alloc(0x100) // * RSA signature of the previous hash. We don't have the keys
	]);

	let payloadContentHeader = Buffer.alloc(0x1C);

	payloadContentHeader.writeBigUInt64BE(programID);
	payloadContentHeader.writeUInt32BE(options.content_datatype, 0xC);
	payloadContentHeader.writeUInt32BE(content.length, 0x10);
	payloadContentHeader.writeUInt32BE(options.ns_data_id, 0x14);
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
		Buffer.alloc(0x100) /// * RSA signature of the previous hash. We don't have the keys
	]);

	const container = Buffer.concat([
		contentHeader,
		payloadContentHeader,
		content
	]);

	const IV = process.env.NODE_ENV === 'test' ? Buffer.alloc(12) : crypto.randomBytes(12);

	// * Main BOSS file
	const header = Buffer.alloc(0x28);

	header.write('boss', 0);
	header.writeUInt32BE(BOSS_CTR_VER, 0x4);
	header.writeUInt32BE(header.length + container.length, 0x8); // * Total BOSS file size. Decrypted and encrypted lengths are the same
	header.writeBigUInt64BE(options.release_date, 0xC);
	header.writeUInt16BE(1, 0x14); // * Always 1
	// * Skip 2 bytes of padding
	header.writeUInt16BE(2, 0x18); // * Hash type. 2 = SHA-256
	header.writeUInt16BE(2, 0x1A); // * RSA type. 2 = RSA-2048
	IV.copy(header, 0x1C);

	const cipher = crypto.createCipheriv('aes-128-ctr', aesKey, Buffer.concat([IV, Buffer.from('\x00\x00\x00\x01')]));

	const encrypted = Buffer.concat([cipher.update(container), cipher.final()]);

	return Buffer.concat([
		header, encrypted
	]);
}

module.exports = {
	decrypt3DS,
	encrypt3DS
};