"""Byte-preserving CTF codecs and explicit-key cryptography; no eval/exec."""
import base64,binascii,hashlib,html,json,re,urllib.parse

VALUES='富强 民主 文明 和谐 自由 平等 公正 法治 爱国 敬业 诚信 友善'.split()
CODECS=['base64_decode','base64_encode','base64url_decode','base64url_encode','base32_decode','base32_encode',
        'base85_decode','base85_encode','hex_decode','hex_encode','url_decode','url_encode','html_decode','html_encode',
        'unicode_decode','rot13','caesar','caesar_all','atbash','reverse_text','reverse_bytes','ascii_shift',
        'binary_decode','decimal_decode','octal_decode','core_values_decode','core_values_encode','xor','xor_single_byte','replace']
CIPHERS=['AES-CBC','AES-ECB','AES-CTR','AES-GCM','DES-CBC','3DES-CBC','RC4','XOR']

def material(value,fmt='hex'):
    if fmt=='hex':
        value=re.sub(r'\s+','',value)
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2})*',value):raise ValueError('十六进制应为完整字节，不能包含 0x 前缀或其他字符。')
        return bytes.fromhex(value)
    if fmt=='base64':return base64.b64decode(value,validate=True)
    if fmt=='utf8':return value.encode('utf-8')
    if fmt=='utf16le':return value.encode('utf-16le')
    raise ValueError('未知的字节表示。')

def readable(data):
    try:return data.decode('utf-8')
    except UnicodeError:return data.decode('utf-8','replace')

def quality(data):
    if not data:return 0
    text=readable(data);score=sum(c.isalnum() or c in ' {}_.,:/@\n-!?' for c in text)/len(text)
    if re.search(r'(?:flag|ctf|picoCTF)\{',text,re.I):score+=5
    score-=text.count('\ufffd')/len(text)
    return round(score,4)

def caesar(text,shift):
    def one(c):
        base=65 if 'A'<=c<='Z' else 97 if 'a'<=c<='z' else None
        return chr((ord(c)-base+shift)%26+base) if base is not None else c
    return ''.join(map(one,text))

def core_decode(text):
    text=''.join(text.split())
    if len(text)%2:raise ValueError('核心价值观编码应由两个汉字的词组成。')
    try:items=[VALUES.index(text[i:i+2]) for i in range(0,len(text),2)]
    except ValueError:raise ValueError('存在不属于核心价值观词表的字符。')
    digits=[];i=0
    while i<len(items):
        n=items[i];i+=1
        if n>=10:
            if i==len(items):raise ValueError('扩展数字缺少后一词。')
            tail=items[i];i+=1
            if tail>9:raise ValueError('扩展数字的第二词必须在前十词内。')
            n=(10 if n==10 else 6)+tail
        if n>15:raise ValueError('还原数字超出十六进制范围。')
        digits.append(format(n,'x'))
    if len(digits)%2:raise ValueError('解码结果不是完整字节。')
    return bytes.fromhex(''.join(digits))

def transform(data,op,p):
    if op not in CODECS:raise ValueError('不支持的转换。')
    if op.endswith('_decode') and op.startswith(('base64','base32','base85')):data=re.sub(rb'\s+',b'',data)
    if op=='base64_decode':return base64.b64decode(data,validate=True),None
    if op=='base64_encode':return base64.b64encode(data),None
    if op=='base64url_decode':return base64.b64decode(data+b'='*((-len(data))%4),altchars=b'-_',validate=True),None
    if op=='base64url_encode':return base64.urlsafe_b64encode(data),None
    if op=='base32_decode':return base64.b32decode(data,casefold=True),None
    if op=='base32_encode':return base64.b32encode(data),None
    if op=='base85_decode':return base64.b85decode(data),None
    if op=='base85_encode':return base64.b85encode(data),None
    if op=='hex_encode':return data.hex().encode(),None
    if op=='hex_decode':return material(data.decode('ascii'),'hex'),None
    if op=='reverse_bytes':return data[::-1],None
    if op=='url_decode':return urllib.parse.unquote_to_bytes(data.decode('ascii')),None
    if op=='url_encode':return urllib.parse.quote_from_bytes(data,safe='').encode(),None
    if op in ('xor','xor_single_byte'):
        if op=='xor':
            key=material(p.get('key',''),p.get('key_format','hex'))
            if not key:raise ValueError('XOR 需要非空密钥。')
            return bytes(v^key[i%len(key)] for i,v in enumerate(data)),None
        candidates=[(i,bytes(v^i for v in data)) for i in range(256)]
        candidates.sort(key=lambda row:quality(row[1]),reverse=True)
        rows=[[f'{k:02x}',quality(v),readable(v)[:2000]] for k,v in candidates]
        return candidates[0][1],dict(columns=['单字节密钥 HEX','可读性排序（仅线索）','UTF-8 预览'],rows=rows,note='下方列出 256 个密钥候选，.bin 导出的是可读性排名第一项。排名不等于正确答案，须结合题意、文件格式或已知明文复核。')
    text=data.decode(p.get('encoding','utf-8'),'strict')
    if op=='html_decode':text=html.unescape(text)
    elif op=='html_encode':text=html.escape(text)
    elif op=='unicode_decode':
        text=re.sub(r'\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2}))',lambda m:chr(int(next(v for v in m.groups() if v is not None),16)),text)
    elif op=='rot13':text=caesar(text,13)
    elif op=='caesar':text=caesar(text,int(p.get('shift',13)))
    elif op=='caesar_all':
        rows=[[i,caesar(text,-i)] for i in range(26)]
        return text.encode('utf-8'),dict(columns=['向后移动位数','候选文本'],rows=rows,note='表格列出 26 种凯撒候选，.bin 保留输入文本。找到有依据的候选后，选择“凯撒 · 指定位移”，填入对应负数位移，再导出选定结果。')
    elif op=='atbash':text=''.join(chr(155-ord(c)) if 'A'<=c<='Z' else chr(219-ord(c)) if 'a'<=c<='z' else c for c in text)
    elif op=='reverse_text':text=text[::-1]
    elif op=='ascii_shift':
        shift=int(p.get('shift',0))
        if not -255<=shift<=255:raise ValueError('字符位移范围 -255～255。')
        text=''.join(chr(ord(c)+shift) for c in text)
    elif op in ('binary_decode','decimal_decode','octal_decode'):
        base={'binary_decode':2,'decimal_decode':10,'octal_decode':8}[op]
        parts=text.split()
        if base==2 and len(parts)==1:
            if len(text)%8:raise ValueError('连续二进制串长度应为 8 的倍数。')
            parts=[text[i:i+8] for i in range(0,len(text),8)]
        values=[int(x,base) for x in parts]
        if any(v<0 or v>255 for v in values):raise ValueError('字节值超出 0～255。')
        return bytes(values),None
    elif op=='core_values_decode':return core_decode(text),None
    elif op=='core_values_encode':
        words=[]
        for d in data.hex():
            n=int(d,16);words.extend([VALUES[n]] if n<10 else [VALUES[10],VALUES[n-10]])
        text=''.join(words)
    elif op=='replace':
        mapping=json.loads(p.get('mapping','{}'))
        if not isinstance(mapping,dict) or len(mapping)>256 or any(not isinstance(k,str) or not isinstance(v,str) or len(k)!=1 for k,v in mapping.items()):raise ValueError('替换表应为 JSON 对象，键必须是单个字符。')
        text=''.join(mapping.get(c,c) for c in text)
    return text.encode('utf-8'),None

def cipher(data,p):
    from Crypto.Cipher import AES,DES,DES3,ARC4
    from Crypto.Util.Padding import pad,unpad
    name=p.get('algorithm','AES-CBC');direction=p.get('direction','decrypt')
    if name not in CIPHERS or direction not in ('encrypt','decrypt'):raise ValueError('加密算法或方向无效。')
    key=material(p.get('key',''),p.get('key_format','hex'))
    if not key:raise ValueError('请输入已知密钥，不能从密文直接推出密钥。')
    if name=='XOR':return transform(data,'xor',p)[0],{}
    if name=='RC4':return ARC4.new(key).encrypt(data),{}
    lib=AES if name.startswith('AES') else DES3 if name.startswith('3DES') else DES
    mode=name.split('-')[-1];iv=material(p.get('iv',''),'hex')
    if mode=='ECB':c=lib.new(key,lib.MODE_ECB)
    elif mode=='CBC':c=lib.new(key,lib.MODE_CBC,iv=iv)
    elif mode=='CTR':
        if len(iv)!=16:raise ValueError('AES-CTR 请输入 16 字节的初始计数块（IV）。')
        c=lib.new(key,lib.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big'))
    elif mode=='GCM':
        if not iv:raise ValueError('AES-GCM 需要 nonce（填写在 IV 中）。')
        c=lib.new(key,lib.MODE_GCM,nonce=iv)
        aad=material(p.get('aad',''),'hex')
        if aad:c.update(aad)
        if direction=='encrypt':
            result,tag=c.encrypt_and_digest(data);return result,dict(tag_hex=tag.hex(),nonce_hex=iv.hex())
        tag=material(p.get('tag',''),'hex')
        if not tag:raise ValueError('AES-GCM 解密必须提供认证标签 tag。')
        return c.decrypt_and_verify(data,tag),dict(authentication='verified')
    else:raise ValueError('不支持的模式。')
    padded=p.get('padding','pkcs7')=='pkcs7' and mode in ('CBC','ECB')
    if direction=='encrypt':return c.encrypt(pad(data,lib.block_size) if padded else data),{}
    result=c.decrypt(data)
    return (unpad(result,lib.block_size) if padded else result),{}

def digest(data,algorithm):
    if algorithm=='ntlm':
        from Crypto.Hash import MD4
        return MD4.new(data.decode('utf-8').encode('utf-16le')).hexdigest()
    if algorithm not in ('md5','sha1','sha256','sha512'):raise ValueError('不支持的摘要算法。')
    return hashlib.new(algorithm,data).hexdigest()

def hash_candidates(target,algorithm,words,limit=100000):
    target=target.strip().lower()
    lengths={'md5':32,'sha1':40,'sha256':64,'sha512':128,'ntlm':32}
    if algorithm not in lengths or not re.fullmatch('[0-9a-f]{'+str(lengths.get(algorithm,0))+'}',target):raise ValueError('摘要格式或长度与算法不符。')
    checked=0
    for word in words:
        if checked>=limit:break
        word=word.rstrip('\r\n');checked+=1
        if digest(word.encode('utf-8'),algorithm)==target:return dict(found=True,candidate=word,checked=checked,algorithm=algorithm,note='候选计算出的摘要相同；这是候选验证，不是哈希逆运算。')
    return dict(found=False,checked=checked,algorithm=algorithm,note='本候选集未命中，不代表不存在口令。')
