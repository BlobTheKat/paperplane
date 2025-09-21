import net from 'net'
import { connect, TLSSocket } from 'tls'
import { resolveMx } from 'dns'
import { _internedBuffers, Mail } from './mail.js'
import crypto from 'crypto'
import fs from 'fs'

export const PIPELINING = 1, MIMEUTF8 = 2, SMTPUTF8 = 4, CHUNKING = 8, BINARYMIME = 16

export class SMTPClient extends Map{
	debug = null
	#sessions = new Map()
	privKey = null
	constructor(host = 'mail.paperplane', key, selector = 'mail'){
		super()
		this.host = host
		if(key) this.setPrivateKey('', key, selector)
	}
	/**
	 * Add a private key override
	 * @param {string?} host Host for which to override the private key to use. Set to '' or null to set the default (fallback) private key
	 * @param {string | Buffer} key Key contents (buffer) or file path (string). Should be in PEM format
	 * @param {string} [selector] DMARC selector, as you set it in your DNS settings. Default value: 'mail'
	 */
	setPrivateKey(host, key, selector = 'mail'){
		const privKey = crypto.createPrivateKey({
			format: 'pem',
			key: typeof key != 'string' ? key : fs.readFileSync(key)+''
		})
		privKey.selector = selector
		if(host) super.set(host, privKey)
		else this.privKey = privKey
	}
	/**
	 * Remove a private key override
	 * @returns Whether the override existed (and thus was deleted)
	 */
	removePrivateKey(host){ return host ? super.delete(host) : this.privKey ? (this.privKey = null, true) : false }
	getSession(hostname, cb){
		if(!hostname) return void cb(null)
		let sock = this.#sessions.get(hostname)
		if(typeof sock == 'number'){
			// Dont-try-again guard
			if(Date.now() < sock) return void cb(null)
		}else if(sock instanceof Array) return void sock.push(cb)
		else if(sock){
			const pr = cb(sock)
			if(typeof pr?.then == 'function'){
				const arr = []; let i = 0
				this.#sessions.set(hostname, arr)
				const done = () => {
					while(i < arr.length){
						const pr = arr[i++](sock)
						if(typeof pr?.then == 'function'){
							pr.then(done, err => { done(); throw err })
							return
						}
					}
					this.#sessions.set(hostname, sock)
				}
				pr.then(done, err => { done(); throw err })
			}
			return
		}
		const cbs = [cb]
		this.#sessions.set(hostname, cbs)
		this.debug?.('SMTPCLI>>Resolving %s...', hostname)
		resolveMx(hostname, (_, recs) => {
			const targets = recs?.length ?
				recs.sort((a, b) => b.priority - a.priority).map(a => a.exchange)
			: [hostname]
			this.#connect(hostname, targets, 0, cbs)
		})
	}

	#connect(hostname, targets, retry, cbs){
		if(!targets.length){
			this.debug?.('SMTPCLI>>No available server found for @%s', hostname)
			this.#sessions.set(hostname, Date.now() + 3600e3)
			for(const c of cbs) c(null)
			return
		}
		let stage = 0
		this.debug?.('SMTPCLI>>Trying '+targets[targets.length-1]+':25')
		let sock = net.createConnection(25, targets[targets.length-1], () => {
			this.debug?.('SMTPCLI>>Connected!')
			if(!retry) sock.write(`EHLO ${this.host}\r\n`)
			sock.removeAllListeners('error')
			sock.on('error', _ => {})
		})
		sock.setKeepAlive(true, 60e3)
		sock.setTimeout(60e3)
		if(this.debug) sock.write = buf => {
			this.debug?.('SMTPCLI>>\x1b[32mC: %s\x1b[m', buf.toString().trim())
			net.Socket.prototype.write.call(sock, buf)
		}
		const buffered = []
		let bufferedSize = 0, lineStart = Date.now()
		const TLS = 1073741824
		let ext = 0, maxSize = Infinity
		let lineCb = null, linesBuffered = [], linesLengthBuffered = 0
		const ondata = buf => {
			let i = 0
			while(i < buf.length){
				const j = buf.indexOf(10, i)
				if(j < 0){
					if(Date.now() - lineStart > 120e3 || (bufferedSize += buf.length - i) > 65536) return void sock.destroy()
					buffered.push(i ? buf.subarray(i) : buf)
					return
				}
				if(j > i){
					if(Date.now() - lineStart > 120e3 || (bufferedSize += j - i) > 65536) return void sock.destroy()
					buffered.push(buf.subarray(i, j))
				}
				i = j+1
				lineStart = Date.now(); bufferedSize = 0
				const line = Buffer.concat(buffered).toString().trim()
				buffered.length = 0
				this.debug?.('SMTPCLI>>\x1b[33mS: %s\x1b[m', line)
				if(stage < 0){
					if(lineCb) lineCb(line)
					else if((linesLengthBuffered += line.length) < 1048576) linesBuffered.push(line)
					else return void sock.destroy()
					continue
				}
				if(retry && !stage && line.startsWith('220')){
					sock.write(`EHLO ${this.host}\r\n`)
					continue
				}
				switch(stage){
					case 0: case 1:
						if(!line.startsWith('250')) break
						if(stage){
							const extStr = line.slice(4).toUpperCase()
							if(extStr == 'STARTTLS') ext |= TLS
							else if(extStr == 'PIPELINING') ext |= PIPELINING
							else if(extStr == '8BITMIME') ext |= MIMEUTF8
							else if(extStr == 'SMTPUTF8') ext |= SMTPUTF8
							else if(extStr == 'BINARYMIME') ext |= BINARYMIME
							else if(extStr == 'CHUNKING') ext |= CHUNKING
							else if(extStr.startsWith('SIZE ')) maxSize = +extStr.slice(5)
						}else stage = 1
						if(line[3] != ' ');
						else if(!(sock instanceof TLSSocket)){
							// Finished
							if(ext&TLS){
								sock.write('STARTTLS\r\n')
								stage = 2
							}else{
								// TLS not supported :(
								sock.removeAllListeners('close')
								sock.end()
								return err(null)
							}
						}else{
							sock.extensions = ext
							sock.maxMessageSize = maxSize
							sock.line = () => {
								if(linesBuffered.length){
									const l = linesBuffered
									linesLengthBuffered -= l.length
									return Promise.resolve(l)
								}else return stage == -1 ? new Promise(r => lineCb = r) : Promise.resolve('')
							}
							let i = 0
							const done = () => {
								if(sock.closed) return
								while(i < cbs.length){
									const pr = cbs[i++](sock)
									if(typeof pr?.then == 'function'){
										pr.then(done, err => { done(); throw err })
										return
									}
								}
								if(this.#sessions.has(hostname)) this.#sessions.set(hostname, sock)
								sock.unref()
								return false
							}
							stage = -1
							done()
							sock.removeAllListeners('close')
						}
						break
					default:
						if(!line.startsWith('220')) break
						stage = 0; ext = 0
						// start TLS
						sock.removeAllListeners('data')
						sock.removeAllListeners('close')
						this.debug?.('SMTPCLI>>Upgrading to TLS...')
						sock = connect(sock, { socket: sock, servername: targets[targets.length-1] }, () => {
							this.debug?.('SMTPCLI>>TLS connected!')
							if(!retry) sock.write(`EHLO ${this.host}\r\n`)
						})
						if(this.debug) sock.write = buf => {
							this.debug?.('SMTPCLI>>\x1b[32mC: %s\x1b[m', buf.toString().trim())
							TLSSocket.prototype.write.call(sock, buf)
						}
						sock.on('data', ondata)
						sock.on('close', err)
				}
			}
		}
		sock.on('data', ondata)
		const err = v => {
			this.debug?.('SMTPCLI>>Failed: '+v)

			if(stage < 0){
				if(lineCb) lineCb('')
				stage = -2
				linesBuffered.length = 0
				this.#sessions.delete(hostname)
				return
			}

			// 3 for network issues, 2 for clean closes
			if(++retry < 3 - (v === false)) return this.#connect(hostname, targets, retry, cbs)
			targets.pop()
			this.#connect(hostname, targets, 0, cbs)
		}
		sock.on('timeout', () => sock.destroy())
		sock.on('error', err)
		sock.on('close', err)
	}

	flushCaches(){
		for(const {0: key, 1: v} of this.#sessions){
			if(typeof v == 'number') this.#sessions.delete(key)
			else if(v instanceof TLSSocket){
				v.end()
				this.#sessions.delete(key)
			}
		}
	}

	/**
	 * Send an email using the current configuration.
	 * @param {string} from It is good practice to set from parameter to the same as the Mail `From` header, but not always a requirement. The `From` header will be shown to the recipient when present, falling back to this value when absent.
	 * Note that the email's `From` header should be covered by a DKIM private key (see setPrivateKey()), eg user@domain-i-control.com else DKIM may fail and the email may be rejected as spam
	 * @param {string|string[]} to Recipient(s) to send the email to
	 * @param {Mail} mail Mail object to send. Some headers will be normalized or added to maximize chance of delivery (e.g `Message-ID`, `DKIM-Signature`, `Date`, ...)
	 * @returns {Promise<string[]>} a list of recipients for which delivery failed
	 */
	send(from, to, mail, transport = ''){ return new Promise(r => {
		const body = { dot: null, chunked: null, mail }
		from = from.trim()
		const failed = []
		let todo = 1
		const fin = f => { if(f) failed.push(f); --todo || r(failed.flat(1)) }
		if(transport) this.getSession(transport, sock =>
			this.#send(sock, from, to = Array.isArray(to) ? to.map(a => a.trim()) : [to.trim()], body).then(fin, () => (failed.push(to), this.debug?.('SMTPCLI>>%o', e), fin())))
		else if(Array.isArray(to)){
			if(!to.length) return r([])
			const targets = new Map()
			for(const email of to){
				const ser = Mail.getDomain(email)
				let arr = targets.get(ser)
				if(!arr) targets.set(ser, arr = [email])
				else arr.push(email)
			}
			todo = targets.size
			for(const {0:ser,1:tos} of targets)
				this.getSession(ser, sock => this.#send(sock, from, tos, body).then(fin, e => (failed.push(tos), this.debug?.('SMTPCLI>>%o', e), fin())))
		}else this.getSession(Mail.getDomain(to), sock =>
			this.#send(sock, from, [to = to.trim()], body).then(fin, e => (failed.push(to), this.debug?.('SMTPCLI>>%o', e), fin())))
	}) }
	async #send(sock, from, to, body){
		if(!sock) throw null
		const wait = !(sock.extensions & PIPELINING), suffix = sock.extensions & SMTPUTF8 ? ' SMTPUTF8' : ''
		const suffix2 = suffix + (!(~sock.extensions & (BINARYMIME | CHUNKING)) ? ' BODY=BINARYMIME'  : sock.extensions & MIMEUTF8 ? ' BODY=8BITMIME' : '')
		if(from[0] != '<') from = `<${from}>`
		sock.write(`MAIL FROM:${from+suffix2}\r\n`)
		if(wait && !(await sock.line()).startsWith('250')) throw null
		const f = []
		for(const rcpt of to){
			sock.write(rcpt[0] != '<' ? `RCPT TO:<${rcpt}>${suffix}\r\n` : `RCPT TO:${rcpt+suffix}\r\n`)
			if(wait && !(await sock.line()).startsWith('250')) f.push(rcpt)
		}
		if(!wait){
			if(!(await sock.line()).startsWith('250')) throw null
			for(let i = 0; i < to.length; i++)
				if(!(await sock.line()).startsWith('250')) f.push(to[i])
		}
		if(sock.extensions & CHUNKING){
			const ch = body.chunked ??= body.mail.toBuffer(this, from, true)
			sock.write(`BDAT ${ch.length} LAST\r\n`)
			sock.write(ch)
		}else{
			sock.write(`DATA\r\n`)
			if(!(await sock.line()).startsWith('354')) throw null
			sock.write(body.dot ??= body.mail.toBuffer(this, from, false))
			sock.write(_internedBuffers.end)
		}
		if(!(await sock.line()).startsWith('250')) throw null
		return f
	}
}