const BOSS = require('../..');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THIS KEY YOURSELF
const { BOSS_AES_KEY } = process.env;

const encryptedFilePath = __dirname + '/EU_BGM1.boss';

const decrypted = BOSS.decrypt(encryptedFilePath, BOSS_AES_KEY);

fs.writeFileSync(__dirname + '/EU_BGM1.dec', decrypted);