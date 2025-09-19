import net from 'net'
import tls, { TLSSocket } from 'tls'
import { Mail } from './mail.js'

export class SMTPServer extends Set{
	debug = null

	/**
	 * Maximum message body in bytes. Default: 25MB
	 */
	maxMessageBody = 25 * 1048576
	/**
	 * Called when a server sends us incoming mail.
	 * @type (auth: any?, from: string, tos: string[], mail: Mail, rawMail: Buffer) => string?
	 * @returns An info message if delivery failed, or null if it succeeded
	 */
	onIncoming = null
	/**
	 * Called when a client submits mail to be delivered on their behalf.
	 * @type (auth: any?, from: string, tos: string[], mail: Mail, rawMail: Buffer) => string?
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
	 * Note that onIncoming/onOutgoing may still be fired at any time irrespective of onAuthenticate unless checkAuth is set appropriately. In such cases the `auth` parameter will be null
	 */
	onAuthenticate = (user, pass, isServer) => {
		return { user: Mail.getLocal(user) || user, pass, isServer }
	}
	/**
	 * Check that a session is authenticated before allowing MAIL FROM: commands or invoking callbacks
	 * false: Don't check
	 * true: Check for outgoing (isServer=false)
	 * function: custom logic that returns true to allow or false to reject
	 * @type boolean | (auth: any, isServer: boolean) => boolean
	 */
	checkAuth = false
	/**
	 * Watermark used within the SMTP protocol
	 */
	hostWatermark = 'Mail server'
	/**
	 * Maximum number of target recipients per email that this server can receive or forward
	 */
	maxRecipients = 50
	/**
	 * Whether to reject all emails by default
	 */
	reject = false
	/**
	 * Add an exception to the allowlist/blocklist defined by `reject`
	 * @param {string} server The domain to add as an exception
	 * For forwarded emails, this acts as an exception to email senders ("we will forward anything that is from us")
	 * For incoming emails, this acts as an exception to email recipients ("we will accept anything that is meant for us")
	 */
	addException(server){ super.add(server.toLowerCase()) }
	/**
	 * Remove an exception to the allowlist/blocklist defined by `reject`
	 * @param {string} server The domain to remove
	 * See addException()
	 */
	removeException(server){ return super.delete(server.toLowerCase()) }
	/**
	 * Check if an exception exists to the allowlist/blocklist defined by `reject`
	 * @param {string} server The domain to check
	 * See addException()
	 */
	hasException(server){ return super.has(server.toLowerCase()) }

	#tlsOptions = null
	#handler(type, sock){
		this.debug?.('New client on ' + ['SMTP', 'SMTPS', 'STLS'][type] + ' port')
		if(this.debug){
			const w = sock.write
			sock.write = (buf) => {
				this.debug?.('\x1b[33mS: %s\x1b[m', buf.toString().trimEnd())
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
						this.debug?.('\x1b[32mC:(%d bytes)\x1b[m', buf.length-i)
						return
					}
					body.push(bodyToRead == buf.length ? (i = bodyToRead, buf) : buf.subarray(i, i += bodyToRead))
					this.debug?.('\x1b[32mC:(%d bytes) fin\x1b[m', bodyToRead)
					bodyToRead = 0
					if(stage == 5){
						if(typeof this.checkAuth == 'function' ? !this.checkAuth(auth, !type) : type && this.checkAuth && !auth){
							sock.write('530 Unauthenticated\r\n')
							break
						}
						let err = ''
						stage = 0
						try{
							const rawBody = Buffer.concat(body)
							const r = (type ? this.onOutgoing : this.onIncoming)?.call(this, auth, from, tos.slice(), Mail.fromBuffer(rawBody, true), rawBody, sock.remoteAddress)
							if(typeof r?.then != 'function') err = r ?? ''
						}catch(e){ console.error(e); err = 1 }
						sock.write(err ? '550 '+(typeof err == 'string' ? err.replace(/[\r\n]/g, ' ') : 'Internal server error')+'\r\n' : '250 Message queued\r\n')
						body.length = bodyLen = 0
						from = ''; tos.length = 0
					}else sock.write('250 Received\r\n')
				}
				if(i >= buf.length) return
				if(stage == 3){ let i1 = i; while(true){
					const j = buf.indexOf(10, i1)
					if(j < 0){
						body.push(i ? buf.subarray(i) : buf)
						this.debug?.('\x1b[32mC:(%d bytes)\x1b[m', buf.length-i)
						return
					}
					let k = j, b = buf, bi = body.length
					for(let i = 3; i >= 0; i--){
						if(!k) k = (b = body[--bi]) ? b.length : 0
						if(!k || b[--k] != ((0x0D2E0A0D>>i*8)&255)){ k = -1; break }
					}
					if(k < 0){ i1 = j+1; continue }
					if(j+1 > i){
						body.push(buf.subarray(i, j+1))
						this.debug?.('\x1b[32mC:(%d bytes) fin\x1b[m', j+1-i)
					}
					if(typeof this.checkAuth == 'function' ? !this.checkAuth(auth, !type) : type && this.checkAuth && !auth){
						sock.write('530 Unauthenticated\r\n')
						break
					}
					let err = ''
					stage = 0
					try{
						const rawBody = Buffer.concat(body)
						const r = (type ? this.onOutgoing : this.onIncoming)?.call(this, auth, from, tos.slice(), Mail.fromBuffer(rawBody, false), rawBody, sock.remoteAddress)
						if(typeof r?.then != 'function') err = r ?? ''
					}catch(e){ console.error(e); err = 1 }
					sock.write(err ? '550 '+(typeof err == 'string' ? err.replace(/[\r\n]/g, ' ') : 'Internal server error')+'\r\n' : '250 Message queued\r\n')
					body.length = bodyLen = 0
					from = ''; tos.length = 0
					i = j+1
					break
				} if(i >= buf.length) return }
				const j = buf.indexOf(10, i)
				if(j < 0){
					buffered.push(new Uint8Array(buf.buffer, buf.byteOffset + i, buf.length - i))
					return
				}
				if(j > i) buffered.push(new Uint8Array(buf.buffer, buf.byteOffset + i, j - i))
				i = j+1
				const line = Buffer.concat(buffered).toString().trim()
				buffered.length = 0
				this.debug?.('\x1b[32mC: %s\x1b[m', line)

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
					case -1:
						sock.write('503 Bad order\r\n')
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
					stage = 4 + (data.slice(-5).toUpperCase() == ' LAST')
					continue
				}
				if(!hostname){
					if(verb == 'HELO'){
						sock.write('250 '+this.hostWatermark+' at your service\r\n')
						hostname = data
					}else if(verb == 'EHLO'){
						sock.write(`250-${this.hostWatermark} at your service\
\r\n250-${sock instanceof TLSSocket ? 'AUTH PLAIN LOGIN' : 'STARTTLS'}\r\n250-PIPELINING\r\n250-BINARYMIME\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-CHUNKING\r\n250 SIZE ${this.maxMessageBody>>>0}\r\n`)
						hostname = data
					}else if(verb == 'QUIT'){
						sock.write('221 Bye\r\n')
						sock.end()
						return
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
							this.debug?.('\x1b[33mS: %s\x1b[m', buf.toString().trimEnd())
							w.call(sock, buf)
						}
					}
					sock.on('secureConnect', () => sock.write('220 '+this.hostWatermark+' ESMTP Paperplane\r\n'))
					sock.on('data', ondata)
					sock.on('error', () => sock.destroy())
					hostname = ''
					break
				}
				case 'AUTH': {
					const method = data.slice(0, 6).toUpperCase()
					if(method == 'PLAIN '){
						let str = ''
						try{
							// Don't allow (user+pass).length > 65536
							if(data.length > 87389) throw null
							str = atob(data.slice(5).trim())
							if(!str || str.charCodeAt()) throw null
							const j = str.indexOf('\0', 1)
							if(j < 0) throw null
							const r = this.onAuthenticate?.(str.slice(1, j), str.slice(j+1), !type) ?? null
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
					}else if(method == 'LOGIN '){
						sock.write('334 VXNlcm5hbWU6\r\n')
						stage = 1
					}else{
						sock.write('500 Method not supported\r\n')
					}
				} break
				case 'MAIL': {
					if(typeof this.checkAuth == 'function' ? !this.checkAuth(auth, !type) : type && this.checkAuth && !auth){
						sock.write('530 Unauthenticated\r\n')
						break
					}
					let p = data.slice(5).trimStart()
					let i = 1
					if(p[1] == '"') while(true){
						i = p.indexOf('"', i+1)
						if(i < 0) break
						let j = i
						while(p[--j] == '\\');
						if((j-i)&1) break
					}
					if(i >= 0) i = p.indexOf('>', i)
					if(data.slice(0, 5).toUpperCase() != 'FROM:' || p[0] != '<' || i < 0){
						sock.write('500 Malformed command\r\n')
						break
					}
					if(from){
						sock.write('503 Wrong order\r\n')
						break
					}
					const ser = Mail.getServer(p = p.slice(1, i))
					if(type && (!ser || (super.has(ser) ^ this.reject))){
						sock.write('550 Server does not handle that email domain\r\n')
						break
					}
					from = p
					sock.write('250 Ok\r\n')
				} break
				case 'RCPT': {
					let p = data.slice(3).trimStart()
					let i = 1
					if(p[1] == '"') while(true){
						i = p.indexOf('"', i+1)
						if(i < 0) break
						let j = i
						while(p[--j] == '\\');
						if((j-i)&1) break
					}
					if(i >= 0) i = p.indexOf('>', i)
					if(data.slice(0, 3).toUpperCase() != 'TO:' || p[0] != '<' || i < 0){
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
					const ser = Mail.getServer(p = p.slice(1, i))
					if(!type && (!ser || (super.has(ser) ^ this.reject))){
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
					sock.write('354 End data with <CR><LF>.<CR><LF>\r\n')
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
					stage = 4 + (data.slice(-5).toUpperCase() == ' LAST')
				} break
				case 'QUIT':
					sock.write('221 Bye\r\n')
					sock.end()
					return
				case 'RSET':
					from = ''
					tos.length = 0
					body.length = 0; bodyLen = 0
					sock.write('250 Ok\r\n')
					break
				default:
					sock.write('500 Unknown command\r\n')
					break
				} //switch
			}
		}
		sock.on('data', ondata)
		sock.on('error', () => sock.destroy())
	}
	/**
	 * Create an SMTP server
	 * @param  {...string} hosts Empty = allow-all server. Otherwise, this represents a list of email domains to allowlist for incoming/outgoing, see addException()
	 */
	constructor(...hosts){
		if(hosts.length == 1 && Array.isArray(hosts[0])) hosts = hosts[0]
		if(hosts.length){
			super(hosts)
			this.reject = true
		}else super()
	}
	#smtpServer = null
	#smtpsServer = null
	#stlsServer = null
	/**
	 * @param {import('tls').SecureContextOptions} opts Set TLS options (certificate, ...)
	 */
	setTLS(opts){
		this.#tlsOptions = opts
		this.#smtpServer?.setSecureContext(opts)
	}
	/**
	 * @param {import('tls').SecureContextOptions} opts TLS options (certificate, ...)
	 */
	async listen(tlsOpts, host = '0.0.0.0', smtpPort = 25, smtpsPort = 465, stlsPort = 587){
		if(tlsOpts) this.#tlsOptions = tlsOpts
		return new Promise(r => {
			let todo = 0, done = () => --todo||r()
			if(smtpPort && !this.#smtpServer)
				this.#smtpServer = net.createServer(this.#handler.bind(this, 0)).listen(smtpPort, host, done), todo++
			if(smtpsPort && !this.#smtpsServer)
				this.#smtpsServer = tls.createServer(tlsOpts, this.#handler.bind(this, 1)).listen(smtpsPort, host, done), todo++
			if(stlsPort && !this.#stlsServer)
				this.#stlsServer = net.createServer(this.#handler.bind(this, 2)).listen(stlsPort, host, done), todo++
			if(!todo) r()
		})
	}
}