import { Mail } from "./mail.js"
import { SMTPClient } from "./smtpcli.js"
import { SMTPServer } from "./smtpser.js"
import fs from 'fs'

const cli = new SMTPClient('blobk.at', 'dkim.key', 'mail2')
const TO = 'mat.reiner@icloud.com'
const code = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000
const c1 = Math.floor(code/1000), c2 = code-c1*1000
const mail = new Mail({
	from: 'Host <noreply@blobk.at>',
	to: `Recipient <${TO}>`,
	subject: 'Test email',
}, `Hello, world!`)

cli.send('noreply@blobk.at', TO, mail).then(failed => {
	if(!failed.length) console.info('\x1b[32mAll sent!\x1b[m')
	else for(const f of failed) console.error('\x1b[31m× %s\x1b[m', f)
})


const ser = new SMTPServer('blobk.at')

await ser.listen({
	key: fs.readFileSync('../.key'),
	cert: fs.readFileSync('../.pem')
})
console.log('\x1b[32mSMTP servers listening on :25, :465, :587\x1b[m')

// Check that `auth` is truthy before accepting commands or calling onOutgoing()
ser.checkAuth = true
ser.onOutgoing = (from, tos, mail, auth) => {
	console.log('\x1b[35mOutgoing from %s to %s\n%o', from, tos, mail)
	// from is guaranteed to match our filter ['blobk.at']
	if(Mail.getLocal(from) != auth.user) return 'Not allowed to send from that email'
	mail.normalize(from)
	// TODO: if `tos` includes some emails controlled by us, bypass network and store directly
	cli.send(from, tos, mail).then(failed => {
		// TODO: "Undelivered mail returned to sender"?
		if(!failed.length) console.info('\x1b[32mAll sent!\x1b[m')
		else for(const f of failed) console.error('\x1b[31m× %s\x1b[m', f)
	})
}

ser.onIncoming = (from, tos, mail, _) => {
	console.log('\x1b[35mIncoming from %s to %s\n%o', from, tos, mail)
	// tos is guaranteed to all match our filter ['blobk.at']
	mail.normalize(from)
	for(const to of tos){
		// TODO: store mail
	}
}