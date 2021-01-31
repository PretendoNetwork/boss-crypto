const BOSS = require('../..');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THIS KEY YOURSELF
const { BOSS_AES_KEY } = process.env;

const encryptedFilePath = __dirname + '/EU_BGM1.dec';

const encrypted = BOSS.encrypt3DS(encryptedFilePath, BOSS_AES_KEY, {
	program_id: 0x0004001000022900, // can also be named "title_id"
	content_datatype: 65537,
	ns_data_id: 36,
});

fs.writeFileSync(__dirname + '/EU_BGM1.boss', encrypted);