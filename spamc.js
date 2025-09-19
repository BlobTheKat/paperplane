import net from 'net'
import tls from 'tls'

export class SpamAssassinClient{
	// 15sec
	timeout = 15e3

	thresholdOverride = NaN

	constructor(host = '127.0.0.1', port = 783, secure = false) {
		this.host = host
		this.port = port
		this.secure = secure
	}
	get(msg, symbols = false){ return new Promise(r => {
		if (typeof msg === "string")
			msg = Buffer.from(msg)
		else if(!(msg instanceof Uint8Array) && !(msg instanceof ArrayBuffer))
			msg = Buffer.alloc(0)
		// Trim leading/trailing new lines from Buffer (if any)
		let trimStart = -1, trimEnd = msg.length+1
		const end = msg.length
		while(++trimStart < end){
			const byte = msg[trimStart]
			if (byte !== 10 && byte !== 14 && byte !== 32)
				break
		}
		while(--trimEnd > 0){
			const byte = msg[trimEnd-1]
			if (byte !== 10 && byte !== 14 && byte !== 32)
				break
		}
		if(trimStart > 0 || trimEnd < end) msg = msg.subarray(trimStart, trimEnd)
		const res = { code: -1, score: NaN, threshold: 5, spam: false, rules: [] }
		const create = (this.secure ? tls : net).createConnection
		const onopen = () => {
			sock.removeAllListeners('error')
			sock.write(symbols ? "SYMBOLS SPAMC/1.5\r\n" : "CHECK SPAMC/1.5\r\n");
			sock.write(`Content-length: ${msg.length + 2}\r\n${(this.thresholdOverride == this.thresholdOverride ? `Required-Score: ${this.thresholdOverride}\r\n` : '')}\r\n`)
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

			const m = status.match(/SPAMD\/([0-9\.\-]+)\s([0-9]+)\s([0-9A-Z_]+)/y)
			if(!m) return r(res)
			const code = +m[2]
			if(Number.isNaN(code)) return r(res)
			res.code = code
			const match = (headers.get('spam')??'').match(/(True|False)\s*;\s*(-?[0-9\.]+)\s*\/\s*(-?[0-9\.]+)\s*(?:;((?:\s*\S)*))?/y)
			if(!match) return r(res)
			res.spam = match[1] == 'True'
			res.score = +match[2]
			res.threshold = +match[3]
			if(match[4]) res.rules = match[4].trimStart().split(/\s*/g)
			r(res)
		})
		sock.on('error', () => r(res))
		sock.setTimeout(this.timeout)
		sock.on('timeout', () => r(res))
	}) }
}