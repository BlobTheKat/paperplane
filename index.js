import { Mail } from "./mail.js"
import { SMTPClient } from "./smtpcli.js"
import { SMTPServer } from "./smtpser.js"

const cli = new SMTPClient('blobk.at', 'dkim.key', 'mail2')
cli.debug = console.info
const TO = 'mat.reiner@icloud.com'

const code = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000

const c1 = Math.floor(code/1000), c2 = code-c1*1000
const mail = new Mail({
	from: '"Locus" <noreply@blobk.at>',
	to: `Customer <${TO}>`,
	subject: 'Locus Verification Code',
	'content-type': 'text/html; charset="UTF-8"',
}, `<html><style>@font-face{font-family:R;src:url('https://picfunk.art/locus.woff2')}</style><body style="font-size:20px;font-family:R,Arial;font-weight:bold;overflow:hidden;width:100%;height:400px;margin:0;padding:0;background-color:#000;color:white !important"><table background="https://i.imgur.com/1xvwsSg.png" style="border-spacing:0;text-align:center;background-size:cover;background-position:center top;width:100%;height:100%;padding:130px 0"><tbody><tr><td><span style="color:#08f">Your verification code is</span></td></tr><tr><td><a style="color:#f42;font-size:1.5em;cursor:text;-webkit-tap-highlight-color:transparent;user-select:all;-webkit-user-select:all" href>${c1.toString().padStart(3, '0')} ${c2.toString().padStart(3, '0')}</a></td></tr><tr><td><em style="font-size:0.75em;font-style:italic;color:#08f8">This is your code only, don't share it with anyone</span></td></tr></tbody></table></body></html>`)


/*cli.send('auth@blobk.at', TO, mail).then(failed => {
	if(!failed.length) console.info('\x1b[32mAll sent!\x1b[m')
	for(const f of failed) console.error('\x1b[31m× %s\x1b[m', f)
})*/
const ser = new SMTPServer('blobk.at')


await ser.listen()
console.log('\x1b[32mSMTP servers listening on :25, :465, :587\x1b[m')

ser.onOutgoing = (from, tos, mail, auth) => {
	console.log('outgoing',from,tos,mail,auth)
	// from is guaranteed to match our filter ['blobk.at']
	if(Mail.getLocal(from) != auth.user) return 'Not allowed to send from that email'
	mail.normalize(from)
	// TODO: if `tos` includes some emails controlled by us, bypass network and store directly
	cli.send(from, tos, mail).then(failed => {
		// TODO: "Undelivered mail returned to sender"?
	})
}

ser.onIncoming = (from, tos, mail, _) => {
	console.log('incoming',from,tos,mail,auth)
	// tos is guaranteed to all match our filter ['blobk.at']
	mail.normalize(from)
	for(const to of tos){
		// TODO: store mail
	}
}