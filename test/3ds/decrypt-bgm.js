const BOSS = require('../..');
const fs = require('fs');
require('dotenv').config();

// PROVIDE THIS KEY YOURSELF
const { BOSS_AES_KEY } = process.env;

const encryptedFilePath = __dirname + '/EU_BGM1';

const container = BOSS.decrypt(encryptedFilePath, BOSS_AES_KEY);

console.log(container);

fs.writeFileSync(__dirname + '/EU_BGM1.dec', container.content);