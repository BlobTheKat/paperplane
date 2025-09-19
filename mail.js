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
	}
	setHeader(k, v){ super.set(k.toLowerCase(), (''+v).trim()) }
	getHeader(k){ return super.get(k.toLowerCase()) }
	hasHeader(k){ return super.has(k) }
	set body(a){
		this.#body = Buffer.from(a || '')
	}
	get body(){ return this.#body }
	toBuffer(norm = null, from = '', chunking = false){
		// Assume utf-8 support
		let headers = ''
		const arr = [null]
		const h = norm ? crypto.createHash('sha256') : null
		if(!chunking){
			// dot stuffing
			let i = 0
			const body = this.#body
			if(body[0] == 46) arr.push(_internedBuffers.dot)
			while(true){
				const j = body.indexOf('\n.', i)
				if(j < 0) break
				const a = body.subarray(i, j+2)
				arr.push(a, _internedBuffers.dot)
				if(h) h.update(a), h.update(_internedBuffers.dot)
				i = j+2
			}
			if(i < body.length){
				const a = body.subarray(i)
				arr.push(a)
				if(h) h.update(a)
			}
			arr.push(_internedBuffers.end)
			if(h) h.update('\r\n')
		}else{
			arr.push(this.#body)
			if(h) h.update(this.#body)
		}
		if(norm){
			const host = Mail.getServer(from)
			if(!host) throw "Invalid 'From:' email address"
			const key = norm.get(host) ?? norm.privKey
			const now = Math.floor(Date.now()*.001)+''
			headers = `From: ${super.get('from') ?? from}\r\nDate: ${super.get('date') ?? new Date().toUTCString().replace('GMT', '+0000')}\r\nSubject: ${super.get('subject') ?? ''}\r\nContent-Type: ${super.get('content-type') ?? 'text/plain;charset=utf-8'}\r\nMIME-Version: ${super.get('mime-version') ?? '1.0'}\r\nMessage-ID: ${super.get('message-id') ?? this.#genId(now, from)}\r\nDKIM-Signature: v=1;a=rsa-sha256;d=${host};s=${key.selector};h=from:date:subject:content-type:mime-version:message-id;t=${now};bh=${h.digest('base64')};b=`
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
	normalize(from = ''){
		const display = Mail.getDisplayName(super.get('from') ?? '')
		if(from){
			from = from.trim()
			super.set('from', display ? from[0] == '<' ? display+' '+from : `${display} <${from}>` : from)
		}
		const dateHeader = super.get('date')
		if(!dateHeader || Number.isNaN(Date.parse(dateHeader))) super.set('date', new Date().toUTCString().replace('GMT', '+0000'))
		if(!super.has('message-id'))
			super.set('message-id', this.#genId(undefined, from))
	}
	#genId(now = Math.floor(Date.now()*.001)+'', from = super.get('from')){
		const rand = new Int32Array(4)
		for(let i = 0; i < 4; i++) rand[i] = Math.floor(Math.random() * 4294967296)
		return `<pplane-${now}-${Buffer.from(rand.buffer).toString('base64url')}@${Mail.getServer(from)}>`
	}
	get id(){
		let id = super.get('message-id')
		if(!id) super.set('message-id', id = this.#genId())
		return id
	}
	get size(){
		let i = this.body.length + 2
		for(const {0:k,1:v} of this) i += k.length + v.length + 4
		return i
	}
	get headerCount(){ return super.size }
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
		const sep = buf.indexOf('\n\r\n')
		let body = sep >= 0 ? buf.slice(sep+3) : Buffer.alloc(0)
		if(!chunking){
			if(body.toString('ascii', -5) == '\r\n.\r\n') body = body.subarray(0, -5)
			// dot unstuff
			let i = 0
			const arr = []
			while(true){
				const j = body.indexOf('\n.', i)
				if(j < 0) break
				arr.push(body.subarray(i, j+1))
				i = j+2
			}
			if(i < body.length) arr.push(body.subarray(i))
			if(arr.length > 1) body = Buffer.concat(arr)
		}
		m.#body = body
		let last = null, lastv = ''
		for(const h of (sep >= 0 ? buf.toString('utf8', 0, sep) : buf.toString('utf8')).split('\n')){
			if((h[0] == ' ' || h[0] == '\t') && typeof last == 'string'){
				m.setHeader(last, lastv += h.trimStart())
				continue
			}
			const colon = h.indexOf(':')
			if(colon < 0) continue
			m.setHeader(last = h.slice(0, colon), lastv = h.slice(colon+1).trimEnd())
		}
		return m
	}
	static encode(buf, m){
		buf.u8arr(m.body)
		buf.v32(m.size)
		for(const {0: k, 1: v} of m)
			buf.str(k), buf.str(v)
	}
	static decode(buf, m = new Mail()){
		m.body = buf.u8arr()
		let i = buf.v32()
		while(i--)
			m.setHeader(buf.str(), buf.str())
		return m
	}
}
const prewritten = ['from', 'date', 'subject', 'content-type', 'message-id', 'mime-version']

const end = Buffer.from('\r\n.\r\n')
const _internedBuffers = {
	end, newline: end.subarray(0, 2),
	dot: end.subarray(2, 3)
}