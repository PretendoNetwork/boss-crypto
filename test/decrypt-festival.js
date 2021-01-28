const BOSS = require('..');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THESE KEYS YOURSELF
const { BOSS_AES_KEY, BOSS_HMAC_KEY } = process.env;

const encryptedFilePath = __dirname + '/Festival.boss';

const decrypted = BOSS.decrypt(encryptedFilePath, BOSS_AES_KEY, BOSS_HMAC_KEY);

fs.writeFileSync(__dirname + '/Festival.byml', decrypted);