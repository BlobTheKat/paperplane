import { resolve } from 'dns'
import net from 'net'
import tls from 'tls'

export class SpamAssassin extends Map{

	/**
	 * Change the spamhaus host used for detecting blocked IPs
	 */
	spamhaus = 'zen.spamhaus.org'

	/**
	 * Request timeout in milliseconds
	 */
	timeout = 15e3

	/**
	 * Optionally override the default spam threshold
	 */
	threshold = 5

	/**
	 * Whether to also request which symbols were triggered for that email
	 */
	getSymbols = true

	/**
	 * Create a client for these connection details
	 * For domain sockets, set host to the path and port to 0
	 */
	constructor(host = '127.0.0.1', port = 783, secure = false) {
		super()
		this.host = host
		this.port = port
		this.secure = secure
	}
	check(msg, ip = '', threshold = this.threshold){ return new Promise(r => {
		const res = { code: -1, score: NaN, threshold, get spam(){ return this.score >= this.threshold }, symbols: [], blocked: false }
		let todo = 1
		if(ip){
			todo++
			if(ip.includes(':')){
				// ipv6
				const parts = ip.split(':')
				const hole = parts.indexOf('')
				for(let i = 0; i < parts.length; i++){
					const p = parts[i], l = p.length
					parts[i] = l > 3 ? `${p[3]}.${p[2]}.${p[1]}.${p[0]}` : l < 2 ? l ? `${p[0]}.0.0.0` : '0.0.0.0' : l == 2 ? `${p[1]}.${p[0]}.0.0` : `${p[2]}.${p[1]}.${p[0]}.0`
				}
				if(hole && parts.length <= 8){
					let h = '0.0.0.0'
					for(let i = parts.length; i < 8; i++) h += '.0.0.0.0'
					parts[hole] = h
				}
				ip = parts.reverse().join('.')
			}
			resolve(ip + '.' + this.spamhaus, (_, b) => {
				if(b) res.blocked = true
				--todo || r(res)
			})
		}
		if (typeof msg === "string")
			msg = Buffer.from(msg)
		else if(!(msg instanceof Uint8Array) && !(msg instanceof ArrayBuffer))
			msg = Buffer.alloc(0)
		// Trim leading/trailing new lines from Buffer (if any)
		let trimEnd = msg.length+1
		const end = msg.length
		//while(++trimStart < end){
		//	const byte = msg[trimStart]
		//	if (byte !== 10 && byte !== 13 && byte !== 32)
		//		break
		//}
		while(--trimEnd > 0){
			const byte = msg[trimEnd-1]
			if (byte !== 10 && byte !== 13)
				break
		}
		if(trimEnd < end) msg = msg.subarray(0, trimEnd)
		const create = (this.secure ? tls : net).createConnection
		const onopen = () => {
			sock.removeAllListeners('error')
			sock.write((this.getSymbols ? "SYMBOLS SPAMC/1.5\r\n" : "CHECK SPAMC/1.5\r\n") + `Content-length: ${msg.length + 2}\r\n\r\n`)
			sock.write(msg)
			sock.write("\r\n")
		}
		const sock = this.port ? create(this.port, this.host, onopen) : create(this.host, onopen)
		let respData = ''
		sock.on('data', ch => respData += ch)
		sock.on('end', () => {
			let split = respData.indexOf('\r\n\r\n')
			if(split < 0) split = respData.length
			let h = respData.slice(0, split)
			const headers = new Map(), body = respData.slice(split+4)
			split = h.indexOf('\r\n')
			if(split < 0) split = h.length
			const status = h.slice(0, split)
			h = h.slice(split+2)
			for(const line of h.split('\r\n')){
				split = line.indexOf(':')
				if(split < 0) split = line.length
				headers.set(line.slice(0, split).trim().toLowerCase(), line.slice(split+1).trim())
			}
			sock.destroy()

			const code = +status.match(/SPAMD\/([0-9\.\-]+)\s([0-9]+)\s([0-9A-Z_]+)/y)?.[2]
			if(Number.isNaN(code)) return --todo||r(res)
			res.code = code
			const match = (headers.get('spam')??'').match(/(True|False)\s*;\s*(-?[0-9\.]+)\s*\/\s*(-?[0-9\.]+)\s*(?:;((?:\s*\S)*))?/y)
			if(!match) return --todo||r(res)
			res.score = +match[2]
			const sym = match[4] || body
			if(sym) for(const s of res.symbols = sym.trim().split(/\s+|,/g))
				res.score += super.get(s) ?? 0
			--todo||r(res)
		})
		sock.on('error', () => (--todo||r(res), sock.destroy()))
		sock.setTimeout(this.timeout)
		sock.on('timeout', () => (--todo||r(res), sock.destroy()))
	}) }
}