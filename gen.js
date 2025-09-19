#!/usr/bin/env node
import fs from 'fs'
import crypto from 'crypto'

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
	modulusLength: 2048,
	publicKeyEncoding: { type: 'spki', format: 'pem' },
	privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
})
console.warn('\x1b[33mSet the following records on your domain\n\n\x1b[32mTXT          \x1b[m%s\n\x1b[32mTXT\x1b[m %s', '_dmarc   v=DMARC1;p=reject;sp=reject;pct=100;rua=mailto:\x1b[90m<report_email>\x1b[m;', 'mail._domainkey   v=DKIM1;k=rsa;t=s;p='+publicKey.trim().split('\n').slice(1,-1).join(''))

fs.writeFileSync(process.argv[2] || 'dkim.key', privateKey)