import crypto from 'crypto'

let random = null
let randomi = 16384

const concat = arr => {
	let i = 0
	for(const n of arr) i += typeof n == 'number' ? 1 : n.length
	const res = Buffer.alloc(i)
	i = 0
	for(const n of arr){
		if(typeof n == 'number') res[i++] = n
		else res.set(n, i), i += n.length
	}
	return res
}

export class Mail extends Map{
	#body
	/**
	 * Shorthand constructor
	 * @param {{[key: string]: string}} headers Mail headers
	 * @param {Buffer | string | undefined} body Mail body
	 */
	constructor(headers, body){
		super()
		if(typeof headers == 'object' && !(headers instanceof Uint8Array) && !(headers instanceof ArrayBuffer)){
			for(const k in headers)
				super.set(k.toLowerCase(), (''+headers[k]).trim())
			headers = body
		}
		this.#body = Buffer.from(headers || '')
	}
	/**
	 * Set mail header
	 * @param {string} k Header key, which will be lowercased
	 * @param {string | Buffer} v Header value, any leading/trailing whitespace be trimmed
	 */
	setHeader(k, v){ super.set(k.toLowerCase(), (''+v).trim()) }
	/**
	 * Get mail header
	 * @param {string} k Header key, which will be lowercased
	 */
	getHeader(k){ return super.get(k.toLowerCase()) }
	/**
	 * Check if mail has a header (even if it is empty)
	 * @param {string} k Header key, which will be lowercased
	 */
	hasHeader(k){ return super.has(k.toLowerCase()) }
	/**
	 * Remove a mail header
	 * @param {string} k Header key, which will be lowercased
	 */
	removeHeader(k){ return super.delete(k.toLowerCase()) }
	/**
	 * Email body, as a buffer. Getter/setter, which converts any assigned value to a buffer
	 */
	set body(a){ this.#body = Buffer.from(a || '') }
	get body(){ return this.#body }

	/**
	 * Serialize an email
	 * @param {import('./smtpcli.js').SMTPClient} [norm] SMTPClient object to use for DKIM signatures
	 * @param {string} [from] Optionally use a fallback `from` address if the header is not present
	 * @param {boolean} [chunking=true] Whether to serialize for BDAT commands (true) or DATA / RETR (false). If false, essentially applies dot-stuffing. It does not append \r\n.\r\n for you.
	 * @returns {Buffer}
	 */
	toBuffer(norm = null, from = '', chunking = true){
		from = super.get('from') ?? from
		// Assume utf-8 support
		let headers = '', h = null, key = null, host = ''
		const arr = [null]
		if(norm){
			h = crypto.createHash('sha256')
			host = from ? Mail.getDomain(from) : ''
			key = host ? norm.get(host) || norm.privKey : norm.privKey
		}
		const body = this.#body
		let end = body.length
		while(end >= 2 && body[end-1] == 10 && body[end-2] == 13) end -= 2
		end += 2
		if(!chunking){
			// dot stuffing
			let i = 0
			if(body[0] == 46) arr.push(_internedBuffers.dot)
			while(true){
				const j = body.indexOf('\n.', i)
				if(j < 0) break
				const a = body.subarray(i, j+2)
				arr.push(a, _internedBuffers.dot)
				if(h) h.update(a), h.update(_internedBuffers.dot)
				i = j+2
			}
			const a = body.subarray(i)
			arr.push(a)
			if(h) h.update(end >= body.length ? a : body.subarray(i, end))
		}else{
			arr.push(body)
			if(h) h.update(end < body.length ? body.subarray(0, end) : body)
		}
		if(h && end > body.length) h.update('\r\n')
		if(norm){
			const now = Math.floor(Date.now()*.001)+''
			headers = `From: ${from}\r\nDate: ${super.get('date') ?? new Date().toUTCString().replace('GMT', '+0000')}\r\nSubject: ${super.get('subject') ?? ''}\r\nContent-Type: ${super.get('content-type') ?? 'text/plain;charset=utf-8'}\r\nMIME-Version: ${super.get('mime-version') ?? '1.0'}\r\nMessage-ID: ${super.get('message-id') ?? this.#genId(now, from)}\r\n`
			if(key){
				headers += `DKIM-Signature: v=1;a=rsa-sha256;d=${host};s=${key.selector};h=from:date:subject:content-type:mime-version:message-id;t=${now};bh=${h.digest('base64')};b=`
				headers += crypto.sign(null, headers, key).toString('base64') + '\r\n'
			}
		}
		for(const {0: k, 1: v} of this){
			const cased = knownHeaders.get(k) ?? ''
			if(norm && cased && (key || k !== 'dkim-signature')) continue
			headers += (cased || k) + ': ' + v + '\r\n'
		}
		headers += '\r\n'
		arr[0] = Buffer.from(headers)
		return concat(arr)
	}
	/**
	 * Normalize the mail object, adding common headers like Date, Message-ID if they are missing
	 * @param {string} [from] Enforce the `From` header to be this address. Preserves display name of old address if there was one
	 */
	normalize(from = ''){
		if(from){
			const display = Mail.getDisplayName(super.get('from') ?? '')
			from = from.trim()
			super.set('from', display ? from[0] == '<' ? display+' '+from : `${display} <${from}>` : from)
		}
		const dateHeader = super.get('date')
		if(!dateHeader || Number.isNaN(Date.parse(dateHeader))) super.set('date', new Date().toUTCString().replace('GMT', '+0000'))
		if(!super.has('message-id'))
			super.set('message-id', this.#genId(undefined, from))
	}
	#genId(now = Math.floor(Date.now()*.001)+'', from = super.get('from')){
		if(randomi >= 16384){
			random = crypto.randomBytes(16384)
			randomi = 0
		}
		return `<paperplane-${now}-${random.subarray(randomi, randomi += 16).toString('base64url')}@${Mail.getDomain(from)}>`
	}
	/**
	 * Get (or generate & set) the Message-ID
	 * @returns {string}
	 */
	getId(){
		let id = super.get('message-id')
		if(!id) super.set('message-id', id = this.#genId())
		return id
	}
	/**
	 * Calculate an estimate size for the mail in bytes. Actual serialized length will vary depending on how it was serialized (e.g chunking? dkim?)
	 * @returns {number}
	 */
	estimateSize(){
		let i = this.body.length + 2
		for(const {0:k,1:v} of this) i += k.length + v.length + 4
		return i
	}
	/**
	 * Number of set headers on this mail
	 */
	get headerCount(){ return super.size }
	/**
	 * Get the domain part of an email
	 * @param {string} email
	 * @returns {string}
	 * @example
	 * ```js
	 * Mail.getDomain(`"John Doe" <johndoe@example.com>`) === 'example.com'
	 * Mail.getDomain(`weird+email@special`) === 'special'
	 * Mail.getDomain(`not an email`) === ''
	 * ```
	 */
	static getDomain(email){
		const split = email.lastIndexOf('@') + 1
		if(!split) return ''
		email = email.slice(split)
		const split2 = email.indexOf('>')
		if(split2 >= 0) email = email.slice(0, split2)
		return email.toLowerCase().trimEnd()
	}
	/**
	 * Get the local part of an email
	 * @param {string} email
	 * @returns {string}
	 * @example
	 * ```js
	 * Mail.getLocal(`"John Doe" <johndoe@example.com>`) === 'johndoe'
	 * Mail.getLocal(`weird+email@special`) === 'weird+email'
	 * Mail.getLocal(`not an email`) === ''
	 * ```
	 */
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
	/**
	 * Get the local part of an email
	 * @param {string} email
	 * @returns {string}
	 * @example
	 * ```js
	 * Mail.getDisplayName(`"John Doe" <johndoe@example.com>`) === '"John Doe"'
	 * Mail.getDisplayName(`weird+email@special`) === ''
	 * Mail.getDisplayName(`not an email`) === ''
	 * ```
	 */
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

	/**
	 * Escape special characters for use in a header, using the format specified by the RFC, e.g `😎` becomes `=?utf-8?q?=F0=9F=98=8E?=`
	 * For strings containing a lot of characters that need escaping, base64 encoding will be used, e.g `=?utf-8?b?8J+Yjg==?=`
	 * @param {string | Buffer} h String to escape
	 * @returns {Buffer}
	 */
	static escapeHeader(h){
		if(!h.buffer) h = Buffer.from(h)
		let q = [_internedBuffers.wordQPPrefix], last = 0, lsp = -2
		let qpThreshold = h.length<30?5:h.length*.2>>>0
		for(let i = 0; i < h.length; i++){
			const ch = h[i]
			q: if(ch==32){
				if(lsp==i-1) break q
				if(i>last) q.push(h.subarray(last, i))
				lsp = i; last=i+1
				q.push(95)
				continue
			}else if(ch==40){
				q.push(h.subarray(last, last = i+1))
				continue
			}else if(ch==61||ch==63){
				if(!qpThreshold) break q
				if(i>last) q.push(h.subarray(last, i))
				q.push(61, 51, ch+7)
				last = i+1; qpThreshold--
				continue
			}else if(ch<32||ch>126){
				if(!qpThreshold) break q
				if(i>last) q.push(h.subarray(last, i))
				q.push(61, (ch<160?48:55)+(ch>>4), ((ch&15)<10?48:55)+(ch&15))
				last = i+1; qpThreshold--
				continue
			}else continue
			return Buffer.from('=?utf-8?b?' + h.toString('base64') + '?=', 'ascii')
		}
		if(q.length==1) return h
		if(last<h.length) q.push(h.subarray(last))
		q.push(63, 61), concat(q)
		return concat(q)
	}
	/**
	 * Unescape special characters from a header value, using the format specified by the RFC, e.g `=?utf-8?q?=F0=9F=98=8E?=` becomes `😎`
	 * See also: `Mail.esapeHeader`
	 * @param {string | Buffer} h String to escape
	 * @returns {Buffer}
	 */
	static unesapeHeader(h){
		if(!h.buffer) h = Buffer.from(h)
		let q = [], last = 0, f = false
		for(let i = 0; i < h.length; i++){
			a: if(h[i] == 61 && h[i+1] === 63){
				const n = h.indexOf(63, i+2)
				if(n<0 || h[n+2] !== 63) break a
				const n2 = h.indexOf(63, n+3)
				if(n2<0 || h[n2+1] !== 61) break a
				f = true
				if(last<i) q.push(h.subarray(last, i))
				switch(h[n+1]){
					case 81: case 113:
						let last2 = n+3
						for(let i = last2; i < n2; i++){
							if(h[i] == 61){
								if(last2 < i) q.push(h.subarray(last2, i))
								const a = h[i+1]&-33, b = h[i+2]&-33
								q.push((a>=16&&a<26?a-16:a>=65&&a<71?a-55:0)<<4|(b>=16&&b<26?b-16:b>=65&&b<71?b-55:0))
								last2 = i+3
							}else if(h[i] == 95){
								if(last2 < i) q.push(h.subarray(last2, i))
								q.push(32)
								last2 = i+1
							}
						}
						if(last2 < n2) q.push(h.subarray(last2, n2))
						break
					case 66: case 98:
						q.push(Buffer.from(h.toString('ascii', n+3, n2), 'base64'))
						break
				}
				last = n2+2; i = n2+1
			}else if(h[i] == 32){
				let j = i
				while(h[i+1] === 32) i++
				j += h[i+1] !== 40
				if(last < j) q.push(h.subarray(last, j))
				last = i+1
			}else if(h[i] === 40){
				const n = h.indexOf(41, i)
				if(n < 0) continue
				if(last < i) q.push(h.subarray(last, i))
				i = n
				while(h[i+1] === 32) i++
				last = i+1
			}
		}
		if(!q.length&&!f) return h
		if(last < h.length) q.push(h.subarray(last))
		return concat(q)
	}
	/**
	 * Parse a mail body according to a `Content-Transfer-Encoding` header
	 * @param {string | Buffer} body Body to parse
	 * @param {string} cte the `Content-Transfer-Encoding` header
	 * @returns {Buffer} the parsed body
	 */
	static parseBody(body, cte){
		cte = cte.toLowerCase()
		if(cte == 'base64'){
			return Buffer.from(body+'', 'base64')
		}else if(cte == 'quoted-printable'){
			if(typeof body == 'string') body = Buffer.from(body)
			let q = [], last = 0
			for(let i = 0; i < body.length; i++){
				if(body[i] == 61){
					if(last<i) q.push(body.subarray(last, i))
					if(body[i+1] === 10){
						last = i+2
					}else if(body[i+1] === 13){
						last = i+2+(body[i+2] === 10)
					}else{
						const a = body[i+1]&-33, b = body[i+2]&-33
						q.push((a>=16&&a<26?a-16:a>=65&&a<71?a-55:0)<<4|(b>=16&&b<26?b-16:b>=65&&b<71?b-55:0))
						last = i+3
					}
				}
			}
			if(!q.length) return body
			if(last < body.length) q.push(body.subarray(last))
			return concat(q)
		}
		return typeof body == 'string' ? Buffer.from(body) : body
	}
	/**
	 * Parse this mail's body according to its `Content-Transfer-Encoding` header
	 * @returns {Buffer} the parsed body
	 */
	parseBody(){ return Mail.parseBody(this.#body, super.get('content-transfer-encoding')??'') }
	/**
	 * Get mail header, and decode it according to `Mail.unescapeHeader`
	 * @param {string} k Header key, which will be lowercased
	 */
	getEncodedHeader(k){ const h = super.get(k.toLowerCase()); return typeof h == 'undefined' ? undefined : Mail.unesapeHeader(h) }
	/**
	 * Set mail header, encoding it according to `Mail.escapeHeader`
	 * @param {string} k Header key, which will be lowercased
	 * @param {string | Buffer} v Header value. Leading/trailing whitespace is encoded and not trimmed
	 */
	setEncodedHeader(k){ super.set(k.toLowerCase(), Mail.esapeHeader(v)) }

	/**
	 * Parse an email from a buffer
	 * @param {Buffer} buf
	 * @param {boolean} [chunking=false] Whether to parse from BDAT commands (true) or DATA / RETR (false). If false, essentially applies dot-unstuffing. It does not remove \r\n.\r\n for you.
	 */
	static fromBuffer(buf, chunking = false){
		const m = new Mail()
		const sep = buf.indexOf('\n\r\n')
		let body = sep >= 0 ? buf.slice(sep+3) : Buffer.alloc(0)
		if(!chunking){
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
			if(arr.length > 1) body = concat(arr)
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
const knownHeaders = new Map()
	.set('from', 'From').set('date', 'Date').set('subject', 'Subject')
	.set('content-type', 'Content-Type').set('message-id', 'Message-ID').set('mime-version', 'MIME-Version')
	.set('dkim-signature', 'DKIM-Signature')

const q1 = Buffer.from('\r\n.\r\n=?utf-8?q?')
export const _internedBuffers = {
	end: q1.subarray(0, 5), newline: q1.subarray(0, 2),
	dot: q1.subarray(2, 3), wordQPPrefix: q1.subarray(5),
}

/**
 * @returns {string} Unique identifier in the format: `paperplane-<unix_timestamp>-r4nDomBaSe64...`
 */
export function uniqueId(){
	if(randomi >= 16384){
		random = crypto.randomBytes(16384)
		randomi = 0
	}
	return `paperplane-${Math.floor(Date.now()*.001)}-${random.subarray(randomi, randomi += 16).toString('base64url')}`
}