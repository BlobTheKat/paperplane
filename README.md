# Paperplane mailer

- 4-way email handling in node.js
- Build-your-own-mail-server, or just the parts that you need
- Direct mail delivery (no paid/free-tier proxies)
- Supports common extensions (pipelining, chunking, utf8, ...)
- SpamAssasin client built-in
- Built to be lightweight and performant
- Built in the big '25 with modern language features and practices

### Sending emails
```js
import { Mail, SMTPClient } from "paperplane-mailer"

// DKIM key can be generated with
// npx paperplane-mailer gen [file?]
const cli = new SMTPClient('myemail.com', './dkim.key', /*selector*/'mail')

const mail = new Mail({
	From: 'Me <me@myemail.com>'
}, `<html><h1>Hello, world!</h1></html>`)

// .send(from, [to...], mail)
cli.send('me@myemail.com', [ 'you@gmail.com' ], mail).then(failed => {
	if(!failed.length){
		console.info('Mail sent to all recipients successfully!')
	}else for(const f of failed){
		console.error('× Failed to send to %s', f)
	}
})
```

### Receiving emails
```js
import { Mail, SMTPServer, SpamAssassin, uniqueId } from "paperplane-mailer"

// Create an SMTP server with a basic filter [ 'myemail.com' ]
// All incoming mail not meant for something@myemail.com is rejected for us
// Leave arguments empty to disable filter
const smtpServer = new SMTPServer('myemail.com')

const tlsOptions = {
	key: fs.readFileSync('myemail.key'),
	cert: fs.readFileSync('myemail.cert')
}
await smtpServer.listen(tlsOptions)
console.info('SMTP servers listening on :25, :465, :587')

// We configure spam-detection using spamassasin and spamhaus
const spamc = new SpamAssassin('127.0.0.1')

smtpServer.onIncoming = async (_, from, toArr, mail, rawMail, ip) => {
	// The from parameter can be used to identify the sender but is not always the same as the `From` header that users see. Keep that in mind, and use the from header if in doubt
	console.log('\x1b[35mIncoming from %s to %s\nIP: %s, headers: %d, body: %d bytes',
		mail.get('from') ?? from, toArr, ip, mail.headerCount, mail.body.length)

	// Mail is checked by spamassasin. IP (if specified) is checked by zen.spamhaus.org
	const spam = await spamc.check(rawMail, ip)

	// SpamAssasin by default doesn't strongly penalize invalid DKIM
	// Despite it being an industry standard and very important in verifying email authenticity
	// Here we automatically spam any email without a valid DKIM signature
	if(!spam.symbols.includes('DKIM_VALID') || spam.spam){
		console.warn('Message flagged as spam with score %d and symbols:\n  %s',
			spam.score, spam.symbols.join(' ')+(spam.blocked ? ' SPAMHAUS_IP_BLOCKED':''))
		return
	}else{
		console.info('Message passed spam test with score %d and symbols:\n  %s',
			spam.score, spam.symbols.join(' '))
	}
	// toArr is guaranteed to all match our filter ['myemail.com']

	// Normalize the email (make sure we have a correct `Date` header, `Message-ID`, ...)
	mail.normalize()

	let count = 0
	for(let to of toArr){
		// Convert user@myemail.com to user
		to = Mail.getLocal(to) || to

		// This example uses in-memory inboxes, see further below
		const inbox = inboxes.get(to)
		if(!inbox) continue

		inbox.add(mail)
		count++
	}
	console.log('Stored to %d inboxes', count)
}

const inboxes = new Map()

class Inbox extends Map{
	constructor({ password = '' }){
		super()
		this.password = password
	}
	add(mail){
		const id = uniqueId() // Unique identifier in the format: paperplane-<unix_timestamp>-r4nDomBaSe64...
		this.set(id, mail)
		return id
	}
}

inboxes.set('john', new Inbox({ password: 'password123' }))

```

### Downloading emails to a client
```js
import { Mail, POPServer } from "paperplane-mailer"

/* Variables from previous example omitted for brevity */

const popServer = new POPServer('myemail.com')

await popServer.listen(tlsOptions)
console.log('\x1b[32mPOP servers listening on :110, :995\x1b[m')

popServer.onAuthenticate = (user, pass) => {
	// TODO: password hashing, timing safe equal, etc...
	const inbox = inboxes.get(user = Mail.getLocal(user) || user)
	if(!inbox || inbox.password !== pass) return null
	return { inbox, username: user }
}
// Prevent calling onGetMessages / onFetchMessage before a successful authentication
popServer.checkAuth = true

popServer.onGetMessages = (auth) => {
	const { inbox, username } = auth

	// Return array of message IDs
	// Conceptually they could be any string as they are just passed to onFetchMessage
	return [...inbox.keys()]
}
popServer.onFetchMessage = (auth, id) => {
	const { inbox, username } = auth

	// Return the Mail object for this message ID, or null
	// This callback is only invoked with message IDs returned by `onGetMessages` with the same auth object so mail being null is a rare edge-case
	return inbox.get(id)
}
```

### Sending emails from a client
```js
import { Mail, SMTPServer } from 'paperplane-mailer'

/* Variables from previous examples omitted for brevity */
//const smtpServer = ...

// Similar to popServer.onAuthenticate
smtpServer.onAuthenticate = (user, pass) => {
	const inbox = inboxes.get(user = Mail.getLocal(user) || user)
	if(!inbox || inbox.password !== pass) return null
	return { inbox, username: user }
}
// Prevent calling onOutgoing before a successful authentication
smtpServer.checkAuth = true

smtpServer.onOutgoing = (auth, from, toArr, mail) => {
	const { inbox, username } = auth

	// from is guaranteed to match our filter ['myemail.com']
	// Unlike onIncoming, `from` here actually means the sender
	// Mail.getLocal('abc@example.com') returns 'abc'
	// We can return a string to indicate to the sender that delivery failed for that reason
	if(Mail.getLocal(from) != auth.user) return 'Not allowed to send from that email'
	
	// Normalize the email, also setting the `From` header based on the value we just checked
	mail.normalize(from)

	cli.send(from, toArr, mail).then(failed => {
		// IDEA: "Undelivered mail returned to sender"?
	})
}
```