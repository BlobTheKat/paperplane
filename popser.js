import net from 'net'
import tls, { TLSSocket } from 'tls'
import { _internedBuffers } from './mail.js'

export class POPServer{
	debug = null
	#stlsServer = null
	#popsServer = null
	#tlsOptions = null

	/**
	 * @type number
	 * Advertise that the server supports automatic message expiry up to this many days
	 * Note that message expiry still has to be requested by the client and not all clients may support it
	 * You may choose to always expire messages yourself and ignore the client's request or take it only as a suggestion
	 * 0 = Don't advertise message expiry commands
	 */
	supportedExpiry = 0

	/**
	 * Called when a client authenticates
	 * @type (user: string, pass: string) => any
	 * The default handler will return an object in the shape { user, pass, messages: [] }
	 * @returns an object (or promise to an object) that will be passed to other callbacks
	 * Throw an error to indicate authentication failure. Returning null or undefined will make it appear to the client as if authentication succeeds.
	 * Note that onFetchMessage/onDeleteMessage/... may still be fired at any time irrespective of onAuthenticate unless checkAuth is set appropriately. In such cases the `auth` parameter will be null
	 */
	onAuthenticate = (user, pass) => {
		return { user: Mail.getLocal(user) || user, pass }
	}
	/**
	 * Called when a client requests a list of messages
	 * @type (auth: any) => Promise<any[]> | any[] | null
	 * @returns an array (or promise to an array) of message IDs
	 */
	onGetMessages = null
	/**
	 * Check that a session is authenticated before invoking callbacks
	 * function: custom logic that returns true to allow or false to reject
	 * @type boolean | (auth: any) => boolean
	 */
	checkAuth = false
	/**
	 * Called when a client fetches a message
	 * @type (auth: any, message: any) => Mail | Promise<Mail>
	 * An element from the list returned by onGetMessages() is passed as the message parameter
	 */
	onFetchMessage = null
	/**
	 * Called when a client requests a message to be deleted, which usually happens when the connection is closed
	 * @type (auth: any, message: any) => void
	 * An element from the list returned by onGetMessages() is passed as the message parameter
	 */
	onDeleteMessages = null

	/**
	 * Called when a client requests a message to be expired after a set number of days
	 * @type (auth: any, message: any, expiryDays: number) => void
	 * An element from the list returned by onGetMessages() is passed as the message parameter
	 */
	onSetExpireRequest = null

	#handler(sock){
		this.debug?.('POP>>New client on ' + (sock instanceof TLSSocket ? 'POPS' : 'POP STLS') + ' port')
		const buffered = []
		let bufferedSize = 0, lineStart = Date.now()
		let user = '', auth = null
		const toDelete = new Set
		let messages = null
		if(this.debug){
			const w = sock.write
			sock.write = (buf) => {
				this.debug?.('POP>>\x1b[33mS: %s\x1b[m', buf.toString().trimEnd())
				w.call(sock, buf)
			}
		}
		sock.setTimeout(60e3)
		sock.on('timeout', () => sock.destroy())
		sock.on('error', _ => {})
		let rl = 0
		const ondata = buf => {
			if(sock.bufferSize > 1048576) return void sock.destroy()
			let i = 0
			while(i < buf.length){
				const j = buf.indexOf('\n', i)
				if(j < 0){
					if(Date.now() - lineStart > 120e3 || (bufferedSize += buf.length - i) > 65542) return void sock.destroy()
					buffered.push(i ? buf.subarray(i) : buf)
					return
				}
				if(j > i){
					if(Date.now() - lineStart > 120e3 || (bufferedSize += j - i) > 65542) return void sock.destroy()
					buffered.push(buf.subarray(i, j))
				}
				i = j+1
				lineStart = Date.now(); bufferedSize = 0
				rl = Math.max(lineStart - 60e3, rl + 100)
				if(rl > lineStart) return void sock.destroy()
				const line = Buffer.concat(buffered).toString().trim()
				buffered.length = 0
				let split = line.indexOf(' ')+1 || line.length+1
				this.debug?.('POP>>\x1b[32mC: %s\x1b[m', line)
				const getMessages = cb => {
					if(typeof this.checkAuth == 'function' ? !this.checkAuth(auth) : this.checkAuth && !auth)
						return void cb([])
					let handled = false
					if(!messages) try{
						const r = this.onGetMessages?.(auth)
						if(typeof r?.then == 'function'){
							r.then(v => {
								messages = Array.isArray(v) ? v : []
								cb(messages)
							}, _ => { cb(messages = []) })
							handled = true
						}else messages = r ?? []
					}catch{ messages = [] }
					if(!handled) cb(messages)
				}
				switch(line.slice(0, split-1).toLowerCase()){
					case 'stls': {
						if(sock instanceof TLSSocket){ sock.write('-ERR Already in TLS'); break }
						sock.write('+OK Upgrading\r\n')
						sock.removeAllListeners('data')
						sock = new TLSSocket(sock, { secureContext: tls.createSecureContext(this.#tlsOptions), isServer: true })
						if(this.debug){
							const w = sock.write
							sock.write = (buf) => {
								this.debug?.('POP>>\x1b[33mS: %s\x1b[m', buf.toString().trimEnd())
								w.call(sock, buf)
							}
						}
						sock.on('secureConnect', () => sock.write('+OK Upgrade successful\r\n'))
						sock.on('data', ondata)
					} break
					case 'capa':
						sock.write('+OK Capabilities\r\nUSER\r\nPIPELINING\r\nUIDL\r\n'+(this.supportedExpiry > 0 ? 'EXPIRE '+this.supportedExpiry+'\r\n' : '')+(sock instanceof TLSSocket ? '.\r\n':'STLS\r\n.\r\n'))
						break
					case 'user':
						user = line.length-split > 65536 ? line.slice(split, split+65536) : line.slice(split)
						sock.write('+OK\r\n')
						break
					case 'pass':
						messages = auth = null
						try{
							const pass = line.length-split > 65536 ? line.slice(split, split+65536) : line.slice(split)
							const r = this.onAuthenticate?.(user, pass) ?? null
							if(typeof r?.then == 'function'){
								r.then(v => {
									auth = v
									sock.write('+OK Logged in\r\n')
								}, _ => { sock.write('-ERR Rejected\r\n') })
							}else{
								auth = r
								sock.write('+OK Logged in\r\n')
							}
						}catch(e){ sock.write('-ERR Rejected\r\n') }
						break
					case 'quit':
						if(typeof this.checkAuth == 'function' ? !this.checkAuth(auth) : this.checkAuth && !auth);
						else if(toDelete.size) this.onDeleteMessages?.(auth, [...toDelete])
						sock.end('+OK Bye\r\n')
						break
					case 'stat': 
						getMessages(m => sock.write('+OK '+m.length+' 65536\r\n'))
						break
					case 'uidl': getMessages(m => {
						let i = 0, s = '+OK '+m.length+' messages\r\n'
						while(i < m.length){
							s += i+1+' '+m[i]+'\r\n'
							i++
						}
						sock.write(s+'.\r\n')
					}); break
					case 'retr': {
						const idx = line.slice(split) - 1 >>> 0
						getMessages(m => {
							if(idx >= m.length) return void sock.write('-ERR No such message\r\n')
							let buf = null
							try{
								const fail = typeof this.checkAuth == 'function' ? !this.checkAuth(auth) : this.checkAuth && !auth
								const r = fail ? null : this.onFetchMessage?.(auth, m[idx])
								if(typeof r?.then == 'function') r.then(r => {
									buf = r ? (r.buffer ? r : r.toBuffer(null, '', false)) : undefined
									if(buf){
										sock.write('+OK '+buf.length+' bytes\r\n')
										sock.write(buf)
										sock.write(_internedBuffers.end)
									}else sock.write('-ERR Email not available\r\n')
								}, _ => { sock.write('-ERR Email not available\r\n') })
								else buf = r ? (r.buffer ? r : r.toBuffer(null, '', false)) : undefined
							}catch(e){ Promise.reject(e) }
							if(buf){
								sock.write('+OK '+buf.length+' bytes\r\n')
								sock.write(buf)
								sock.write(_internedBuffers.end)
							}else if(buf === undefined){
								sock.write('-ERR Email not available\r\n')
							}
						})
					} break
					case 'dele': {
						const idx = line.slice(split) - 1 >>> 0
						getMessages(m => {
							if(idx >= m.length) return void sock.write('-ERR No such message\r\n')
							toDelete.add(m[idx])
							sock.write('+OK marked')
						})
					} break
					case 'rset':
						toDelete.clear()
						sock.write('+OK reset')
						break
					case 'list': {
						const idx = line.slice(split) >>> 0
						getMessages(m => {
							if(idx > m.length) return void sock.write('-ERR No such message\r\n')
							if(idx) return void sock.write('+OK '+idx+' 4096\r\n')
							let i = 0, s = '+OK '+m.length+' messages\r\n'
							while(i < m.length){
								s += i+1+' 4096\r\n'
								i++
							}
							sock.write(s+'.\r\n')
						})
					} break
					case 'noop': sock.write('+OK pong'); break
					case 'expire': if(this.supportedExpiry){
						const split2 = line.indexOf(' ', split)
						const idx = line.slice(split, split2) - 1 >>> 0, exp = +line.slice(split2) || 0
						getMessages(m => {
							if(typeof this.checkAuth == 'function' ? !this.checkAuth(auth) : this.checkAuth && !auth)
								return void sock.write('-ERR Auth error\r\n')
							if(idx >= m.length) return void sock.write('-ERR No such message\r\n')
							try{ this.onSetExpireRequest?.(auth, m[idx], exp) }catch(e){ Promise.reject(e) }
						})
						sock.write('+OK Hint set\r\n')
						break
					} // else fall through
					default: sock.write('-ERR Unknown command\r\n')
				}
			}
		}
		sock.on('data', ondata)
		sock.write('+OK Paperplane POP3 ready\r\n')
	}
	/**
	 * @param {import('tls').SecureContextOptions} opts set TLS options (certificate, ...)
	 */
	setTLS(opts){
		this.#tlsOptions = opts
		this.#popsServer?.setSecureContext(opts)
	}
	/**
	 * @param {import('tls').SecureContextOptions} opts TLS options (certificate, ...)
	 */
	listen(tlsOpts, host = '0.0.0.0', stlsPort = 110, popsPort = 995){
		this.#tlsOptions = tlsOpts
		return new Promise(r => {
			let todo = 0, done = () => --todo||r()
			if(stlsPort && !this.#stlsServer)
				this.#stlsServer = net.createServer(this.#handler.bind(this)).listen(stlsPort, host, done), todo++
			if(popsPort && !this.#popsServer)
				this.#popsServer = tls.createServer(tlsOpts, this.#handler.bind(this)).listen(popsPort, host, done), todo++
			if(!todo) r()
		})
	}
}