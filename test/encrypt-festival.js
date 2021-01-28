const BOSS = require('..');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THESE KEYS YOURSELF
const { BOSS_AES_KEY, BOSS_HMAC_KEY } = process.env;

const decryptedFilePath = __dirname + '/Festival.byml';

// Can also use BOSS.encrypt(decryptedFilePath, 0x20001, BOSS_AES_KEY, BOSS_HMAC_KEY);
const encrypted = BOSS.encryptWiiU(decryptedFilePath, BOSS_AES_KEY, BOSS_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.boss', encrypted);