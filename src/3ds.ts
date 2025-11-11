import crypto from 'node:crypto';
import { md5, getDataFromPathOrBuffer } from '@/util';

export const CTR_BOSS_FLAGS = {
	MARK_ARRIVED_PRIVILEGED: 1n << 0n
} as const;

export type CTRBOSSFlag = (typeof CTR_BOSS_FLAGS)[keyof typeof CTR_BOSS_FLAGS];

export type CTRPayloadContent = {
	payload_content_header_hash: Buffer;
	payload_content_header_hash_signature: Buffer;
	program_id: bigint;
	content_datatype: number;
	ns_data_id: number;
	version: number;
	content: Buffer;
};

export type CTRBOSSContainer = {
	hash_type: number;
	serial_number: bigint; // * Identifier of the container
	iv: Buffer;
	flags: CTRBOSSFlag;
	content_header_hash: Buffer;
	content_header_hash_signature: Buffer;
	payload_contents: CTRPayloadContent[];
};

export type CTRCryptoOptions = {
	program_id?: string | number | bigint; // * Program ID and title ID are aliases
	title_id?: string | number | bigint; // * Program ID and title ID are aliases
	serial_number?: bigint; // * Identifier of the container. Only used in boss.encrypt()
	flags?: CTRBOSSFlag; // * Only used in boss.encrypt()
	content_datatype: number;
	ns_data_id: number;
	version: number;
	content?: string | Buffer; // * Not needed in boss.encrypt()
};

const BOSS_CTR_VER = 0x10001;

// * Not providing the key
const BOSS_AES_KEY_HASH = Buffer.from('86fbc2bb4cb703b2a4c6cc9961319926', 'hex');

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

	// * Parse the BOSS data header
	const data = getDataFromPathOrBuffer(pathOrBuffer);

	const hashType = data.readUInt16BE(0x18);

	if (hashType !== 2) {
		throw new Error('Unknown hash type');
	}

	const serialNumber = data.readBigUInt64BE(0xC);

	const IV = Buffer.concat([
		data.subarray(0x1C, 0x28),
		Buffer.from('\x00\x00\x00\x01')
	]);

	// * Decrypt BOSS content
	const decipher = crypto.createDecipheriv('aes-128-ctr', aesKey, IV);

	const decryptedContent = Buffer.concat([decipher.update(data.subarray(0x28)), decipher.final()]);

	// * Parse content header
	const contentHeader = decryptedContent.subarray(0, 0x132);
	const contentHeaderMagic = contentHeader.subarray(0, 0x10);

	let flags: CTRBOSSFlag = 0n;

	// * Reverse the flag logic for clarity
	if (!(contentHeaderMagic[0] & 0x80)) {
		flags |= CTR_BOSS_FLAGS.MARK_ARRIVED_PRIVILEGED;
	}

	const payloadsCount = contentHeader.readUInt16BE(0x10);
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

	const payloads: CTRPayloadContent[] = [];
	const payloadContents = decryptedContent.subarray(0x132);
	let payloadContentsOffset = 0;
	for (let i = 0; i < payloadsCount; i++) {
		// * Parse the payload content header
		const payloadContentHeader = payloadContents.subarray(payloadContentsOffset, payloadContentsOffset + 0x13C);
		const programID = payloadContentHeader.readBigUInt64BE(); // * This is the app title ID, the wiki calls it the "program ID"
		const contentDataType = payloadContentHeader.readUInt32BE(0xC);
		const contentLength = payloadContentHeader.readUInt32BE(0x10);
		const nsDataID = payloadContentHeader.readUInt32BE(0x14);
		const version = payloadContentHeader.readUInt32BE(0x18);
		const payloadContentHeaderHash = payloadContentHeader.subarray(0x1C, 0x3C);
		const payloadContentHeaderHashSignature = payloadContentHeader.subarray(0x3C, 0x13C);

		const content = payloadContents.subarray(payloadContentsOffset + 0x13C, payloadContentsOffset + 0x13C + contentLength);

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

		payloads.push({
			payload_content_header_hash: payloadContentHeaderHash,
			payload_content_header_hash_signature: payloadContentHeaderHashSignature,
			program_id: programID,
			content_datatype: contentDataType,
			ns_data_id: nsDataID,
			version,
			content
		});

		payloadContentsOffset += 0x13C + contentLength;
	}

	// * We don't do any RSA signature verification because we don't have the public key

	return {
		hash_type: hashType,
		serial_number: serialNumber,
		iv: IV,
		flags: flags,
		content_header_hash: contentHeaderHash,
		content_header_hash_signature: contentHeaderHashSignature,
		payload_contents: payloads
	};
}

export function encrypt3DS(aesKey: string | Buffer, serialNumber: bigint, options: CTRCryptoOptions[], flags?: CTRBOSSFlag): Buffer {
	if (typeof aesKey === 'string') {
		aesKey = Buffer.from(aesKey, 'hex');
	}

	verifyKey(aesKey);

	const payloadCount = options.length;
	let payloadContents: Buffer = Buffer.alloc(0);
	options.forEach((option: CTRCryptoOptions) => {
		if (typeof option.content === 'undefined') {
			throw new Error('No content was set');
		}
		const content = getDataFromPathOrBuffer(option.content);

		let programID: string | number | bigint;

		if (option.program_id) {
			programID = option.program_id;
		} else if (option.title_id) {
			programID = option.title_id;
		} else {
			throw new Error('No program ID set. Set options.program_id or options.title_id');
		}

		if (typeof programID === 'string') {
			programID = BigInt(parseInt(programID, 16));
		}

		if (typeof programID === 'number') {
			programID = BigInt(programID);
		}

		let payloadContentHeader = Buffer.alloc(0x1C);

		payloadContentHeader.writeBigUInt64BE(programID);
		payloadContentHeader.writeUInt32BE(option.content_datatype, 0xC);
		payloadContentHeader.writeUInt32BE(content.length, 0x10);
		payloadContentHeader.writeUInt32BE(option.ns_data_id, 0x14);
		payloadContentHeader.writeUInt32BE(option.version, 0x18);

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

		payloadContents = Buffer.concat([
			payloadContents,
			payloadContentHeader,
			content
		]);
	});

	let contentHeader = Buffer.alloc(0x12);

	// * Reverse the flag logic for clarity
	if (!flags || !(flags & CTR_BOSS_FLAGS.MARK_ARRIVED_PRIVILEGED)) {
		contentHeader[0] |= 0x80;
	}

	contentHeader.writeUInt16BE(payloadCount, 0x10); // * Payload contents count

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

	const container = Buffer.concat([
		contentHeader,
		payloadContents
	]);

	// * vitest sets this to 'test', CICD testing sets this to 'ci'
	const IV = (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'ci') ? Buffer.alloc(12) : crypto.randomBytes(12);

	// * Main BOSS file
	const header = Buffer.alloc(0x28);

	header.write('boss', 0);
	header.writeUInt32BE(BOSS_CTR_VER, 0x4);
	header.writeUInt32BE(header.length + container.length, 0x8); // * Total BOSS file size. Decrypted and encrypted lengths are the same
	header.writeBigUInt64BE(serialNumber, 0xC);
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
