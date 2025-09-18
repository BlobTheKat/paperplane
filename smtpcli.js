import net from 'net'
import { connect, TLSSocket } from 'tls'
import { resolveMx, resolveTxt, reverse } from 'dns'
import { Mail } from './mail.js'
import crypto from 'crypto'
import fs from 'fs'

export const PIPELINING = 1, MIMEUTF8 = 2, SMTPUTF8 = 4, CHUNKING = 8

export class SMTPClient extends Map{
	debug = null
	#sessions = new Map()
	constructor(host, key, selector = 'mail'){
		super()
		this.host = host
		this.privKey = crypto.createPrivateKey({
			format: 'pem',
			key: typeof key != 'string' ? key : fs.readFileSync(key)+''
		})
		this.privKey.selector = selector
		resolveTxt('mail._domainkey.' + host, (err, txt) => {
			if(!txt)
				console.warn('\x1b[33mNo published public key found for %s!', host)
		})
	}
	setPrivateKey(host, key, selector = 'mail'){
		const privKey = crypto.createPrivateKey({
			format: 'pem',
			key: typeof key != 'string' ? key : fs.readFileSync(key)+''
		})
		privKey.selector = selector
		if(host) super.set(host, privKey)
		else this.privKey = privKey
	}
	removePrivateKey(host){ super.delete(host) }
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
				sock.ref()
				const done = () => {
					while(i < arr.length){
						const pr = arr[i++](sock)
						if(typeof pr?.then == 'function'){
							pr.then(done, err => { done(); throw err })
							return
						}
					}
					sock.unref()
					this.#sessions.set(hostname, sock)
				}
				pr.then(done, err => { done(); throw err })
			}
			return
		}
		const cbs = [cb]
		this.#sessions.set(hostname, cbs)
		this.debug?.('Resolving %s...', hostname)
		resolveMx(hostname, (_, recs) => {
			const targets = recs?.length ?
				recs.sort((a, b) => b.priority - a.priority).map(a => a.exchange)
			: [hostname]
			this.#connect(hostname, targets, 0, cbs)
		})
	}

	#connect(hostname, targets, retry, cbs){
		if(!targets.length){
			this.debug?.('No available server found for @%s', hostname)
			this.#sessions.set(hostname, Date.now() + 3600e3)
			for(const c of cbs) c(null)
			return
		}
		let stage = 0
		this.debug?.('Trying '+targets[targets.length-1]+':25')
		let sock = net.createConnection(25, targets[targets.length-1], () => {
			this.debug?.('Connected!')
			if(!retry) sock.write(`EHLO ${this.host}\r\n`)
		})
		sock.setKeepAlive(true, 60e3)
		sock.setTimeout(60e3)
		if(this.debug) sock.write = buf => {
			this.debug?.('\x1b[32mC: %s\x1b[m', buf.toString().trim())
			net.Socket.prototype.write.call(sock, buf)
		}
		const buffered = []
		const TLS = 1073741824
		let ext = 0, maxSize = Infinity
		let lineCb = null, linesBuffered = []
		const ondata = buf => {
			let i = 0
			while(i < buf.length){
				const j = buf.indexOf(10, i)
				if(j < 0){
					buffered.push(new Uint8Array(buf.buffer, buf.byteOffset + i, buf.length - i))
					return
				}
				if(j > i) buffered.push(new Uint8Array(buf.buffer, buf.byteOffset + i, j - i))
				i = j+1
				const line = Buffer.concat(buffered).toString().trim()
				buffered.length = 0
				this.debug?.('\x1b[33mS: %s\x1b[m', line)
				if(stage > 2){
					if(lineCb) lineCb(line)
					else linesBuffered.push(line)
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
								sock.removeAllListeners('error')
								sock.removeAllListeners('close')
								sock.end()
								return err(null)
							}
						}else{
							sock.extensions = ext
							sock.line = () =>
								linesBuffered.length ? Promise.resolve(linesBuffered.shift()) : new Promise(r => lineCb = r )
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
							done()
							stage = 3
							sock.removeAllListeners('error')
							sock.removeAllListeners('close')
						}
						break
					default:
						if(!line.startsWith('220')) break
						stage = 0; ext = 0
						// start TLS
						sock.removeAllListeners('data')
						sock.removeAllListeners('error')
						sock.removeAllListeners('close')
						this.debug?.('Upgrading to TLS...')
						sock = connect(sock, { socket: sock, servername: targets[targets.length-1] }, () => {
							this.debug?.('TLS connected!')
							if(!retry) sock.write(`EHLO ${this.host}\r\n`)
						})
						if(this.debug) sock.write = buf => {
							this.debug?.('\x1b[32mC: %s\x1b[m', buf.toString().trim())
							TLSSocket.prototype.write.call(sock, buf)
						}
						sock.on('data', ondata)
						sock.once('error', err)
						sock.once('close', err)
				}
			}
		}
		sock.on('data', ondata)
		const err = v => {
			if(v === true) return // on('close') where on('error') was also called

			this.debug?.('Failed: '+v)

			// 3 for network issues, 2 for clean closes
			if(++retry < 3 - (v === false)) return this.#connect(hostname, targets, retry, cbs)
			
			targets.pop()
			this.#connect(hostname, targets, 0, cbs)
		}
		sock.once('timeout', () => {
			sock.removeAllListeners('error')
			sock.removeAllListeners('close')
			sock.end()
			this.#sessions.delete(hostname)
		})
		sock.once('error', err)
		sock.once('close', err)
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

	send(from, to, mail, transport = ''){ return new Promise(r => {
		const body = { dot: null, chunked: null, mail }
		from = from.trim()
		const failed = []
		let todo = 1
		const fin = _ => --todo || r(failed.flat(1))
		if(transport) this.getSession(transport, sock =>
			this.#send(sock, from, to = Array.isArray(to) ? to.map(a => a.trim()) : [to.trim()], body, failed).then(fin, () => (failed.push(to), fin())))
		else if(Array.isArray(to)){
			if(!to.length) return
			const toHere = [to[0].trim()], toElsewhere = new Map()
			const server = Mail.getServer(toHere[0])
			for(let i = to.length-1; i >= 0; i--){
				const email = to[i].trim(), ser = Mail.getServer(email)
				if(ser == server){
					toHere.push(email)
					continue
				}
				let arr = toElsewhere.get(ser)
				if(!arr) toElsewhere.set(ser, arr = [email])
				else arr.push(email)
			}
			to = toHere
			todo = toElsewhere.size + 1
			for(const {0:ser,1:tos} of toElsewhere)
				this.getSession(ser, sock => this.#send(sock, from, tos, body, failed).then(fin, () => (failed.push(tos), fin())))
			this.getSession(server, sock => this.#send(sock, from, toHere, body, failed).then(fin, () => (failed.push(toHere), fin())))
		}else this.getSession(Mail.getServer(to), sock =>
			this.#send(sock, from, [to = to.trim()], body, failed).then(fin, () => (failed.push(to), fin())))
	}) }
	async #send(sock, from, to, body, failed){
		if(!sock) throw null
		const wait = !(sock.extensions & PIPELINING), suffix = (sock.extensions & SMTPUTF8 ? ' SMTPUTF8' : '') + (sock.extensions & MIMEUTF8 ? ' BODY=8BITMIME' : '')
		if(from[0] != '<') from = `<${from}>`
		sock.write(`MAIL FROM:${from}\r\n`)
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
		}
		if(!(await sock.line()).startsWith('250')) throw null
		if(f.length) failed.push(f)
	}
}