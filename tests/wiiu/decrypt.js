const assert = require('node:assert');
const { decryptWiiU } = require('../../dist/boss');

require('dotenv').config();

// PROVIDE THESE KEYS YOURSELF
const { BOSS_WIIU_AES_KEY, BOSS_WIIU_HMAC_KEY } = process.env;

const expected = {
	hash_type: 2,
	iv: Buffer.from('00000000000000000000000000000001', 'hex'),
	hmac: Buffer.from('ee7648d9f0a6e6d6b2c0475982b995cf36217d0dad02fe55431e8ae7eb02027e', 'hex'),
	content: Buffer.from('48656c6c6f20576f726c64', 'hex')
};

const encrypted = Buffer.from([
	0x62, 0x6f, 0x73, 0x73, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xa8, 0x5e, 0xdb, 0xd7, 0x87, 0x41, 0x45, 0xfe,
	0x47, 0x86, 0x19, 0x45, 0xf3, 0x94, 0x09, 0xe9, 0xd5, 0xe2,
	0x81, 0xbb, 0x6c, 0xcd, 0xc7, 0xa6, 0x36, 0x40, 0x56, 0xcf,
	0xa8, 0x41, 0x38, 0xf2, 0x51, 0x74, 0x7a, 0xde, 0x1d, 0x78,
	0x85, 0xc3, 0xd4, 0xa3, 0xa5
]);

const decrypted = decryptWiiU(encrypted, BOSS_WIIU_AES_KEY, BOSS_WIIU_HMAC_KEY);

assert.equal(decrypted.hash_type, expected.hash_type, `Decrypted hash type does not match. Expected ${expected.hash_type}. Got ${decrypted.hash_type}`);
assert.ok(expected.iv.equals(decrypted.iv), `Invalid IV. Expected\n\n${expected.iv.toString('hex')}\n\nGot\n\n${decrypted.iv.toString('hex')}`);
assert.ok(expected.hmac.equals(decrypted.hmac), `Invalid HMAC. Expected\n\n${expected.hmac.toString('hex')}\n\nGot\n\n${decrypted.hmac.toString('hex')}`);
assert.ok(expected.content.equals(decrypted.content), `Invalid decrypted content. Expected\n\n${expected.content.toString('hex')}\n\nGot\n\n${decrypted.content.toString('hex')}`);
