import fs from 'node:fs';
import crypto from 'node:crypto';

export function md5(input: crypto.BinaryLike): Buffer {
	return crypto.createHash('md5').update(input).digest();
}

export function getDataFromPathOrBuffer(pathOrBuffer: string | Buffer): Buffer {
	let data: Buffer;

	if (pathOrBuffer instanceof Buffer) {
		data = pathOrBuffer;
	} else {
		data = fs.readFileSync(pathOrBuffer);
	}

	return data;
}