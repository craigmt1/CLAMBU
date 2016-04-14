from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import base64, time, os

#base64 encode/decode
b64e = lambda s: base64.b64encode(s)
b64d = lambda s: base64.b64decode(s)

obj = AES.new('sixteen byte key')
verbose = False

strhex = lambda s: " ".join("{:02x}".format(ord(c)) for c in s)
pad = lambda s, l=16: s + (l - (len(s) % l)) * '\x00' if len(s) % l > 0 else s
split = lambda s, i: (s[:i], s[i:])

def blocks(m, x=16):
    for i in range(len(m) / x): yield m[i*x:(i+1)*x]

def clamburound(m, obj, iv='\x00'*16):
    X, Y = split(obj.encrypt(iv), 8)
    R = X
    if verbose: print (strhex(X), " | ", strhex(Y))
    for block in blocks(m, 16):
        P1, P2 = split(block, 8)
        X, Y = split(obj.encrypt(X+Y), 8)
        R = strxor(P1, X)
        C1 = strxor(P1, X)
        C2 = strxor(P2, Y)
        X, Y = Y, X
        if verbose:
            print strhex(block), " -> ", strhex(C1 + C2)
            print "\tX: %s\tY: %s" % (strhex(X), strhex(Y))
        yield C1 + C2

def clambu_enc(m, obj, iv='\x00'*16):
    m = pad(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
    return b64e(out)

def clambu_dec(m, obj, iv='\x00'*16):
    m = b64d(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
    return out

s = "this is a bigger test of stuff you can do with clambu"
print s
c = clambu_enc(s, obj)
print c
print clambu_dec(c, obj)