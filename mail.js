import crypto from 'crypto'

export class Mail extends Map{
	#body
	constructor(a, b){
		super()
		if(typeof a == 'object' && !(a instanceof Uint8Array) && !(a instanceof ArrayBuffer)){
			for(const k in a)
				super.set(k.toLowerCase(), (''+a[k]).trim())
			a = b
		}
		this.#body = Buffer.from(a || '')
		this.bh = ''
	}
	setHeader(k, v){ super.set(k.toLowerCase(), (''+v).trim()) }
	getHeader(k){ return super.get(k.toLowerCase()) }
	hasHeader(k){ return super.has(k) }
	set body(a){
		this.#body = Buffer.from(a || '')
		this.bh = ''
	}
	get body(){ return this.#body }
	toBuffer(norm = null, from, chunking = false){
		// Assume utf-8 support
		let headers = ''
		const arr = [null]
		const h = norm && !this.bh ? crypto.createHash('sha256') : null
		if(!chunking){
			// dot stuffing
			let i = 0, last = 0
			const body = this.#body
			while(true){
				const j = body.indexOf(46, i)
				if(j < 0) break
				if(!j || (body[j-1]==10 && body[j-2]==10)){
					const a = body.subarray(last, j)
					arr.push(a, _internedBuffers.dot)
					if(h) h.update(a), h.update(_internedBuffers.dot)
					last = j
				}
				i = j+1
			}
			if(last < body.length){
				const a = body.subarray(last)
				arr.push(a)
				if(h) h.update(a)
			}
			arr.push(_internedBuffers.end)
			if(h) h.update('\r\n')
		}else{
			arr.push(this.#body)
			if(h) h.update(this.#body)
		}
		if(h) this.bh = h.digest('base64')
		if(norm){
			const host = Mail.getServer(from)
			if(!host) throw "Invalid 'From:' email address"
			const key = norm.get(host) ?? norm.privKey
			const now = Math.floor(Date.now()*.001)+''
			headers = `From: ${super.get('from') ?? from}\r\nDate: ${super.get('date') ?? new Date().toUTCString().replace('GMT', '+0000')}\r\nSubject: ${super.get('subject') ?? ''}\r\nContent-Type: ${super.get('content-type') ?? 'text/plain;charset=utf-8'}\r\nMIME-Version: 1.0\r\nMessage-ID: <pplane-${now}-${this.bh.slice(0,-1)}@${host}>\r\nDKIM-Signature: v=1;a=rsa-sha256;d=${host};s=${key.selector};h=from:date:subject:content-type:mime-version:message-id;t=${now};bh=${this.bh};b=`
			headers += crypto.sign(null, headers, key).toString('base64') + '\n'
		}
		for(const {0: k, 1: v} of this){
			if(norm && prewritten.includes(k)) continue
			headers += k + ': ' + v + '\r\n'
		}
		headers += '\r\n'
		arr[0] = Buffer.from(headers)
		return Buffer.concat(arr)
	}
	normalize(from){
		const display = Mail.getDisplayName(super.get('from'))
		from = from.trim()
		super.set('from', display ? from[0] == '<' ? display+' '+from : `${display} <${from}>` : from)
		const dateHeader = super.get('date')
		if(!dateHeader || Number.isNaN(Date.parse(dateHeader))) super.set('date', new Date().toUTCString().replace('GMT', '+0000'))
		
	}
	static getServer(email){
		const split = email.lastIndexOf('@') + 1
		if(!split) return ''
		email = email.slice(split)
		const split2 = email.indexOf('>')
		if(split2 >= 0) email = email.slice(0, split2)
		return email.toLowerCase().trimEnd()
	}
	static getLocal(email){
		const split = email.lastIndexOf('@')
		if(split < 0) return ''
		email = email.slice(0, split)
		let i = split
		// Edge cases like "Me <" <"<"@mail.com> where the second < is the one to catch
		if(email[i-1] == '"'){
			i--
			while(true){
				i = email.lastIndexOf('"', i-1)
				if(i <= 0 || email[i-1] != '\\') break
			}
		}
		const split2 = i > 0 ? email.lastIndexOf('<', i-1) : -1
		if(split2 >= 0) email = email.slice(split2+1)
		return email
	}
	static getDisplayName(email){
		email = email.trimStart()
		let i = 0
		if(email[0] == '"'){
			i = 0
			while(true){
				i = email.indexOf('"', i+1)
				if(i < 0) break
				let j = i
				while(email[--j] == '\\');
				if((j-i)&1) break
			}
			if(i < 0) i = 0
		}
		const split = email.indexOf('<', i)
		if(split >= 0) email = email.slice(0, split)
		return email.trimEnd()
	}
	static fromBuffer(buf, chunking = false){
		const m = new Mail()
		if(!chunking && buf.toString('ascii', -5) == '\r\n.\r\n') buf = buf.subarray(0, -5)
		const sep = buf.indexOf('\r\n\r\n')
		m.#body = sep >= 0 ? buf.slice(sep+4) : Buffer.alloc(0)
		for(const h of (sep >= 0 ? buf.toString('utf8', 0, sep) : buf.toString('utf8')).split('\r\n')){
			const colon = h.indexOf(':')
			if(colon < 0) continue
			const name = h.slice(0, colon).toLowerCase(), val = h.slice(colon).trim()
			super.set(name, val)
		}
		return m
	}
}
const prewritten = ['from', 'date', 'subject', 'content-type', 'message-id', 'mime-version']

const end = Buffer.from('\r\n.\r\n')
export const _internedBuffers = {
	end, newline: end.subarray(0, 2),
	dot: end.subarray(2, 3)
}