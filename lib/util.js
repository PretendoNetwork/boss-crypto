const fs = require('fs');
const crypto = require('crypto');

function md5(input) {
	return crypto.createHash('md5').update(input).digest();
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
	md5,
	getDataFromPathOrBuffer
};