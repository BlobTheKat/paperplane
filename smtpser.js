import net, { Socket } from 'net'
import tls, { TLSSocket } from 'tls'
import { Mail } from './mail.js'

export class SMTPServer extends Set{
	debug = null
	maxMessageBody = 25 * 1048576 // 25MB
	/**
	 * Called when a server sends us incoming mail.
	 * @type (from: string, tos: string[], mail: Mail, auth: any?) => string?
	 * @returns An info message if delivery failed, or null if it succeeded
	 */
	onIncoming = null
	/**
	 * Called when a client submits mail to be delivered on their behalf.
	 * @type (from: string, tos: string[], mail: Mail, auth: any?) => string?
	 * @returns An info message if delivery failed, or null if it succeeded
	 * If you are forwarding the email, consider replying with a success right away and deferring the send to reduce latency.
	 */
	onOutgoing = null
	/**
	 * Called when a client (or server) authenticates
	 * @type (user: string, pass: string, isServer: boolean) => any
	 * The default handler will return an object in the shape { user, pass, isServer }
	 * @returns an object (or promise to an object) that will be passed to onIncoming/onOutgoing
	 * Throw an error to indicate authentication failure. Returning null or undefined will make it appear to the client as if authentication succeeds.
	 * Note that onIncoming/onOutgoing may still be fired at any time irrespective of onAuthenticate, it is up to you to verify within those handlers that the client has permission to send based on the auth parameter. By default, if no authentication occured, the auth parameter will be null
	 */
	onAuthenticate = (user, pass, isServer) => {
		return { user, pass, isServer }
	}
	#tlsOptions = null
	hostWatermark = 'Mail server'
	maxRecipients = 50
	addException(server){ super.add(server.toLowerCase()) }
	removeException(server){ return super.delete(server.toLowerCase()) }
	hasException(server){ return super.has(server.toLowerCase()) }
	#handler(type, sock){
		this.debug?.('New client on ' + ['SMTP', 'SMTPS', 'STLS'][type] + ' port')
		if(this.debug){
			const w = sock.write
			sock.write = (buf) => {
				this.debug?.('\x1b[33m%s\x1b[m', buf.toString().trimEnd())
				w.call(sock, buf)
			}
		}
		sock.write('220 '+this.hostWatermark+' ESMTP Paperplane\r\n')
		const buffered = []
		let hostname = '', stage = 0
		let user = '', auth = null
		let from = '', bodyLen = 0
		const body = [], tos = []
		let bodyToRead = 0
		const ondata = buf => {
			let i = 0
			loop: while(i < buf.length){
				if(bodyToRead){
					if(bodyToRead > buf.length-i){
						bodyToRead -= buf.length-i
						body.push(i ? buf.subarray(i) : buf)
						return
					}
					body.push(bodyToRead == buf.length ? buf : buf.subarray(i, i+bodyToRead))
					bodyToRead = 0
					if(stage == 5){
						let err = ''
						try{
							err = (type ? this.onOutgoing : this.onIncoming)?.(from, tos, Mail.fromBuffer(Buffer.concat(body), true), auth) ?? ''
						}catch(e){ Promise.reject(e); err = 1 }
						stage = 0
						sock.write(err ? '550 '+(typeof err == 'string' ? err.replace(/[\r\n]/g, ' ') : 'Internal server error')+'\r\n' : '250 Message queued\r\n')
						body.length = 0
						bodyLen = 0
						from = ''; tos.length = 0
					}
				}
				if(i >= buf.length) return
				if(stage == 3) while(true){
					let i1 = i
					const j = buf.indexOf(10, i1)
					if(j < 0){
						body.push(i ? buf.subarray(i) : buf)
						return
					}
					let k = j, b = buf, bi = body.length
					for(let i = 3; i >= 0; i--){
						if(!k) k = (b = body[--bi]) ? b.length : 0
						if(!k || b[--k] != '\r\n.\r'[i]){ k = -1; break }
					}
					if(k < 0){ i1 = j+1; continue }
					if(j+1 > i) body.push(buf.subarray(i, j+1))
					let err = ''
					try{
						err = (type ? this.onOutgoing : this.onIncoming)?.(from, tos, Mail.fromBuffer(Buffer.concat(body), true), auth) ?? ''
					}catch(e){ Promise.reject(e); err = 1 }
					stage = 0
					sock.write(err ? '550 '+(typeof err == 'string' ? err.replace(/[\r\n]/g, ' ') : 'Internal server error')+'\r\n' : '250 Message queued\r\n')
					body.length = 0
					bodyLen = 0
					from = ''; tos.length = 0
				}
				const j = buf.indexOf(10, i)
				if(j < 0){
					buffered.push(new Uint8Array(buf.buffer, buf.byteOffset + i, buf.length - i))
					return
				}
				if(j > i) buffered.push(new Uint8Array(buf.buffer, buf.byteOffset + i, j - i))
				i = j+1
				const line = Buffer.concat(buffered).toString().trim()
				buffered.length = 0

				switch(stage){
					// AUTH LOGIN
					case 1:
						user = atob(line.length > 87384 ? line.slice(0, 87384) : line)
						sock.write('334 UGFzc3dvcmQ6\r\n')
						stage = 2
						continue loop
					case 2:
						const pass = atob(line.length > 87384 ? line.slice(0, 87384) : line)
						try{
							if(user.length + pass.length > 65536) throw null
							const r = this.onAuthenticate?.(user, pass, !type) ?? null
							if(typeof r?.then == 'function') r.then(v => {
								sock.write('235 Authentication successful\r\n')
								auth = v
							}, () => {
								sock.write('535 Invalid credentials\r\n')
							})
							else{
								sock.write('235 Authentication successful\r\n')
								auth = r
							}
						}catch{
							sock.write('535 Invalid credentials\r\n')
						}
						user = ''; stage = 0
						continue loop
				}

				const sp = line.indexOf(' '), verb = line.slice(0, sp >= 0 ? sp : line.length).toUpperCase(), data = sp >= 0 ? line.slice(sp+1).trimEnd() : ''
				if(stage >= 4){
					if(verb != 'BDAT'){
						sock.write('503 Wrong order\r\n')
						continue
					}
					const len = parseInt(data) >>> 0
					if((bodyLen += len) > this.maxMessageBody){
						sock.write('552 Body too big\r\n')
						bodyLen = 0
						body.length = 0
						stage = 0
						continue
					}
					bodyToRead = len
					stage = 4 + data.slice(-5).toUpperCase() == ' LAST'
					continue
				}
				if(!hostname){
					if(verb == 'HELO'){
						sock.write('250 '+this.hostWatermark+' at your service\r\n')
						hostname = data
					}else if(verb == 'EHLO'){
						sock.write(`250-${this.hostWatermark} at your service\
\r\n250-${sock instanceof TLSSocket ? 'AUTH PLAIN LOGIN' : 'STARTTLS'}\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-CHUNKING\r\n250 SIZE ${this.maxMessageBody>>>0}\r\n`)
						hostname = data
					}else sock.write('503 Impolite\r\n')
					continue
				}
				switch(verb){
				case 'STARTTLS': {
					if(sock instanceof TLSSocket){ sock.write('503 Already in TLS\r\n'); break }
					sock.write('220 Upgrade ready\r\n')
					sock.removeAllListeners('data')
					sock.removeAllListeners('error')
					sock = new tls.TLSSocket(sock, { secureContext: tls.createSecureContext(this.#tlsOptions), isServer: true })
					if(this.debug){
						const w = sock.write
						sock.write = (buf) => {
							this.debug?.('\x1b[33m%s\x1b[m', buf.toString().trimEnd())
							w.call(sock, buf)
						}
					}
					sock.once('secureConnect', () => sock.write('220 '+this.hostWatermark+' ESMTP Paperplane\r\n'))
					sock.on('data', ondata)
					sock.once('error', () => sock.destroy())
					break
				}
				case 'AUTH': {
					const method = data.slice(0, 6).toUpperCase()
					if(method == 'PLAIN'){
						let str = ''
						try{
							// Don't allow (user+pass).length > 65536
							if(data.length > 87389) throw null
							str = atob(data.slice(5).trim())
							if(!str || str.charCodeAt()) throw null
							const j = str.indexOf('\0', 1)
							if(j < 0) throw null
							const r = this.onAuthenticate?.(str.slice(1, j), str.slice(j), !type) ?? null
							if(typeof r?.then == 'function') r.then(v => {
								sock.write('235 Authentication successful\r\n')
								auth = v
							}, () => {
								sock.write('535 Invalid credentials\r\n')
							})
							else{
								sock.write('235 Authentication successful\r\n')
								auth = r
							}
						}catch{
							sock.write('535 Invalid credentials\r\n')
						}
					}else if(method == 'LOGIN'){
						sock.write('334 VXNlcm5hbWU6\r\n')
						stage = 1
					}
				} break
				case 'MAIL': {
					let p = data.slice(5).trimStart()
					if(p.slice(-9).toUpperCase() == ' SMTPUTF8') p = p.slice(0, -9).trimEnd()
					if(data.slice(0, 5).toUpperCase() != 'FROM:' || p[0] != '<' || p[p.length-1] != '>'){
						sock.write('500 Malformed command\r\n')
						break
					}
					if(from){
						sock.write('503 Wrong order\r\n')
						break
					}
					const ser = Mail.getServer(p = p.slice(1, -1))
					if(type && (!ser || (super.has(ser) ^ this.#reject))){
						sock.write('550 Server does not handle that email domain\r\n')
						break
					}
					from = p
					sock.write('250 Ok\r\n')
				} break
				case 'RCPT': {
					let p = data.slice(5).trimStart()
					if(p.slice(-9).toUpperCase() == ' SMTPUTF8') p = p.slice(0, -9).trimEnd()
					if(data.slice(0, 3).toUpperCase() != 'TO:' || p[0] != '<' || p[p.length-1] != '>'){
						sock.write('500 Malformed command\r\n')
						break
					}
					if(!from){
						sock.write('503 Wrong order\r\n')
						break
					}
					if(tos.length >= this.maxRecipients){
						sock.write('550 Maximum number of recipients reached\r\n')
						break
					}
					const ser = Mail.getServer(p = p.slice(1, -1))
					if(!type && (!ser || (super.has(ser) ^ this.#reject))){
						sock.write('550 Server does not handle that email domain\r\n')
						break
					}
					tos.push(p)
					sock.write('250 Ok\r\n')
				} break
				case 'DATA': {
					if(!from || !tos.length){
						sock.write('503 Wrong order\r\n')
						break
					}
					stage = 3
				} break
				case 'BDAT': {
					if(!from || !tos.length){
						sock.write('503 Wrong order\r\n')
						break
					}
					const len = parseInt(data) >>> 0
					if((bodyLen += len) > this.maxMessageBody){
						sock.write('552 Body too big\r\n')
						bodyLen = 0
						body.length = 0
						stage = 0
						break
					}
					bodyToRead = len
					stage = 4 + data.slice(-5).toUpperCase() == ' LAST'
				} break
				case 'QUIT':
					sock.write('221 Bye\r\n')
					sock.end()
					break
				case 'RSET':
					from = ''
					tos.length = 0
					body.length = 0; bodyLen = 0
					sock.write('250 Ok\r\n')
					break
				} //switch
			}
		}
		sock.on('data', ondata)
		sock.once('error', () => sock.destroy())
	}
	constructor(...hosts){
		if(hosts.length == 1 && Array.isArray(hosts[0])) hosts = hosts[0]
		if(hosts.length){
			super(hosts)
			this.#reject = true
		}else super()
	}
	get reject(){ return this.#reject }
	set reject(a){ this.#reject = !!a }
	#reject = false
	#smtpServer = null
	#smtpsServer = null
	#stlsServer = null
	setTLS(opts){
		this.#tlsOptions = opts
		this.#smtpServer?.setSecureContext(opts)
	}
	async listen(tlsOpts, host, smtpPort = 25, smtpsPort = 465, stlsPort = 587){
		if(tlsOpts) this.#tlsOptions = tlsOpts
		if(typeof host == 'function') cb = host, host = ''
		return new Promise(r => {
			let todo = 0, done = () => --todo||r()
			if(smtpPort && !this.#smtpServer)
				this.#smtpServer = net.createServer(this.#handler.bind(this, 0)).listen(smtpPort, host, done), todo++
			if(smtpsPort && !this.#smtpsServer)
				this.#smtpsServer = tls.createServer(tlsOpts, this.#handler.bind(this, 1)).listen(smtpsPort, host, done), todo++
			if(stlsPort && !this.#stlsServer)
				this.#stlsServer = net.createServer(this.#handler.bind(this, 2)).listen(stlsPort, host, done), todo++
		})
	}
}