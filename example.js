import { Mail } from "./mail.js"
import { POPServer } from "./popser.js"
import { SMTPClient } from "./smtpcli.js"
import { SMTPServer } from "./smtpser.js"
import fs from 'fs'
import { SpamAssassinClient } from "./spamc.js"

const cli = new SMTPClient('blobk.at', 'dkim.key', 'mail2')

const tls = {
	key: fs.readFileSync('../.key'),
	cert: fs.readFileSync('../.pem')
}

const smtpServer = new SMTPServer('blobk.at')
const popServer = new POPServer('blobk.at')

await smtpServer.listen(tls)
console.log('\x1b[32mSMTP servers listening on :25, :465, :587\x1b[m')
await popServer.listen(tls)
console.log('\x1b[32mPOP servers listening on :110, :995\x1b[m')

// Check that `auth` is truthy before accepting commands or calling onOutgoing()
smtpServer.checkAuth = true
smtpServer.onOutgoing = (auth, from, tos, mail) => {
	console.log('\x1b[35mOutgoing from %s to %s\nheaders: %d, body: %d bytes', from, tos, mail.headerCount, mail.body.length)
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

const spamc = new SpamAssassinClient('/var/run/spamd.sock', 0)
smtpServer.onIncoming = async (_, from, tos, mail, raw) => {
	console.log('\x1b[35mIncoming from %s to %s\nheaders: %d, body: %d bytes', from, tos, mail.headerCount, mail.body.length)
	const spam = await spamc.get(raw)
	if(spam.spam){
		console.log('\x1b[31mMessage flagged as spam\x1b[m')
		return 'Message flagged as spam'
	}

	// tos is guaranteed to all match our filter ['blobk.at']
	mail.normalize(from)
	let count = 0
	for(let to of tos){
		const i = inboxes.get(to = Mail.getLocal(to) || to)
		if(!i) continue
		i.add(mail)
		count++
	}
	console.log('\x1b[32mStored to %d inboxes', count)
}

const welcomeMail = new Mail({
	Subject: 'Welcome to Paperplane!',
	'Content-Type': 'text/html; charset=utf-8',
	'Message-ID': '<welcome@paperplane>'
}, '<h1>Welcome to Paperplane!</h1>')
welcomeMail.normalize(/*from*/'noreply@paperplane')

class Inbox extends Map{
	constructor(password = ''){
		super()
		this.password = password
		this.add(welcomeMail)
	}
	add(mail){ const {id} = mail; super.set(id, mail); return id }
	toArray(){ return [...this.keys()] }
}

const inboxes = new Map()
for(let user of fs.readFileSync('passwords.env').toString().split('\n')){
	user = user.trim()
	if(!user || user[0] == '#') continue
	const eq = user.indexOf('=')
	const pass = eq < 0 ? '' : user.slice(eq+1)
	user = eq < 0 ? user : user.slice(0, eq)
	inboxes.set(user, new Inbox(pass))
}
console.log('\x1b[32mLoaded %d inboxes\x1b[m', inboxes.size)

popServer.checkAuth = true
popServer.onAuthenticate = (user, pass) => {
	const inbox = inboxes.get(user = Mail.getLocal(user) || user)
	if(!inbox || inbox.password !== pass) throw 'Invalid password'
	return inbox
}

popServer.onGetMessages = (inbox) => inbox.toArray()
popServer.onFetchMessage = (inbox, id) => inbox.get(id)