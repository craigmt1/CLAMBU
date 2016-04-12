from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import base64, time, string, random, os, numpy as np

#base64 encode/decode
b64e = lambda s: base64.b64encode(s)
b64d = lambda s: base64.b64decode(s)

obj = AES.new('sixteen byte key')
#obj = pyaes.AESModeOfOperationECB('sixteen byte key')

strhex = lambda s: " ".join("{:02x}".format(ord(c)) for c in s)

pad = lambda s, l=16: s + (l - (len(s) % l)) * '\x00' if len(s) % l > 0 else s
split = lambda s, i: (s[:i], s[i:])
rev = lambda s: ''.join(reversed(s))

def blocks(m, x=16):
    for i in range(len(m) / x): yield m[i*x:(i+1)*x]

def blocks_inv(c, x=16):
    for i in range(len(c) / x - 1, -1, -1): yield c[i*x:(i+1)*x]

#@profile
def cbc(m, obj, iv='\x00'*16):
    m = pad(m)
    out = ''
    for block in blocks(m):
        iv = strxor(block, iv)
        iv = obj.encrypt(iv)
        out += iv
    return b64e(out)

#@profile
def jambu(m, obj, Y='\x00'*8, X='\x00'*8):
    #round generator
    def jamburound(m, obj, Y='\x00'*8, X='\x00'*8):
        X, Y = split(obj.encrypt(X+Y), 8)
        R = X
        for block in blocks(m, 8):
            P = block
            print strhex(P), " -> ",
            X, Y = split(obj.encrypt(X+Y), 8)
            X = strxor(X, P)
            Y = strxor(Y, R)
            R = strxor(R, X)
            P = strxor(P, Y)
            print strhex(P)
            yield P
    
    m = pad(m)
    out = ''.join([r for r in jamburound(m, obj, Y, X)])
    return b64e(out)

def jambu_inv(c, obj, Y='\x00'*8, X='\x00'*8):
    #round generator
    def jamburound_inv(c, obj, Y='\x00'*8, X='\x00'*8):
        X, Y = split(obj.encrypt(X+Y), 8)
        R = X
        for block in blocks(c, 8):
            C = block
            print strhex(C), " -> ",
            X, Y = split(obj.encrypt(X+Y), 8)
            Y = strxor(Y, R)
            C = strxor(C, Y)
            X = strxor(X, C)
            R = strxor(R, X)
            print strhex(C)
            yield C

    c = b64d(c)
    out = ''.join([r for r in jamburound_inv(c, obj, X, Y)])
    return out

def clambu(m, obj, iv='\x00'*16):
    #round generator
    def clamburound(m, obj, iv='\x00'*16):
        X, Y = split(obj.encrypt(iv), 8)
        R = X
        for block in blocks(m, 16):
            P1, P2 = split(block, 8)
            print strhex(block), " -> ",
            Y, X = split(obj.encrypt(X+Y), 8)
            Y = strxor(Y, P1)
            R = strxor(R, Y)
            print strhex(Y + strxor(X, P2))
            print "\tX: %s\tY: %s" % (strhex(X), strhex(Y))
            yield Y + strxor(X, P2)

    m = pad(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
    return b64e(out)

def clambu_inv(m, obj, iv='\x00'*16):
    #round generator
    def clamburound_inv(m, obj, iv='\x00'*16):
        X, Y = split(obj.encrypt(iv), 8)
        R = X
        for block in blocks(m, 16):
            C1, C2 = split(block, 8)
            print strhex(block), " -> ",
            Y, X = split(obj.encrypt(X+Y), 8)
            Y = strxor(C1, Y)
            R = strxor(R, Y)
            print strhex(Y + strxor(X, C2))
            print "\tX: %s\tY: %s" % (strhex(X), strhex(Y))
            yield Y + strxor(X, C2)

    m = b64d(m)
    out = ''.join([r for r in clamburound_inv(m, obj, iv)])
    return out

#compute execution time of function with supplied arguments over number of iterations
def bmark(func, args, iterations=100):
    start_t = time.time()
    for i in range(iterations): func(*args)
    end_t = time.time()
    print "%s\tEXECUTION TIME FOR %d ITERATIONS: %f" % (func.__name__.upper(), iterations, end_t - start_t)

#@profile
def main():
    m = os.urandom(1000)
    m = pad(m)
    
    bmark(cbc, (m,obj,))
    bmark(jambu, (m,obj,), 1)
#main()

#c = jambu("this is a bigger test", obj)
#print c
#print jambu_inv(c, obj)

c = clambu("this is a bigger test", obj)
print c
print clambu_inv(c, obj)

#openssl aes-128-cbc -e -nosalt -K `xxd -p <<< "sixteen byte key"` -iv 0 -in <( echo -n "print \"CBC-MAC not a hash,\"#####################") | xxd -p | tr -d \\n