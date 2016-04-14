from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import base64, time, string, random, os, numpy as np

#base64 encode/decode
b64e = lambda s: base64.b64encode(s)
b64d = lambda s: base64.b64decode(s)

obj = AES.new('sixteen byte key')

strhex = lambda s: " ".join("{:02x}".format(ord(c)) for c in s)

pad = lambda s, l=16: s + (l - (len(s) % l)) * '\x00' if len(s) % l > 0 else s
split = lambda s, i: (s[:i], s[i:])
rev = lambda s: ''.join(reversed(s))

def blocks(m, x=16):
    for i in range(len(m) / x): yield m[i*x:(i+1)*x]

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

def clamburound(m, obj, iv='\x00'*16):
    X, Y = split(obj.encrypt(iv), 8)
    print (strhex(X), " | ", strhex(Y))
    R = X
    for block in blocks(m, 16):
        print strhex(block), " -> ",
        P1, P2 = split(block, 8)
        X, Y = split(obj.encrypt(X+Y), 8)
        R = strxor(P1, X)
        C1 = strxor(P1, X)
        C2 = strxor(P2, Y)
        X, Y = Y, X
        print strhex(C1 + C2)
        print "\tX: %s\tY: %s" % (strhex(X), strhex(Y))
        yield C1 + C2

def clambu_enc(m, obj, iv='\x00'*16):
    #round generator
    m = pad(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
    return b64e(out)

def clambu_dec(m, obj, iv='\x00'*16):
    #round generator
    m = b64d(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
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

    bmark(jambu, (m,obj,), 1)
#main()

s = "this is a bigger test of stuff you can do with clambu"
print s
c = clambu_enc(s, obj)
print c
print clambu_dec(c, obj)

#openssl aes-128-cbc -e -nosalt -K `xxd -p <<< "sixteen byte key"` -iv 0 -in <( echo -n "print \"CBC-MAC not a hash,\"#####################") | xxd -p | tr -d \\n