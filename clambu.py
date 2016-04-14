#! /usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import base64, time, os, argparse, sys

#base64 encode/decode
b64e = lambda s: base64.b64encode(s)
b64d = lambda s: base64.b64decode(s)

verbose = False

strhex = lambda s: " ".join("{:02x}".format(ord(c)) for c in s) if s != None else "00 " * 16
pad = lambda s, l=16: s + (l - (len(s) % l)) * '\x00' if len(s) % l > 0 else s
split = lambda s, i: (s[:i], s[i:])

def blocks(m, x=16):
    for i in range(len(m) / x): yield m[i*x:(i+1)*x]

def clamburound(m, obj, iv='\x00'*16):
    X, Y = split(obj.encrypt(iv), 8)
    R = X
    #if verbose: print (strhex(X), " | ", strhex(Y))
    for block in blocks(m, 16):
        P1, P2 = split(block, 8)
        X, Y = split(obj.encrypt(X+Y), 8)
        R = strxor(P1, X)
        C1, C2 = strxor(P1, X), strxor(P2, Y)
        X, Y = Y, X
        if verbose:
            print strhex(block), " -> ", strhex(C1 + C2)
            #print "\tX: %s\tY: %s" % (strhex(X), strhex(Y))
        yield C1 + C2

def clambu_enc(m, obj, iv='\x00'*16):
    m = pad(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
    return b64e(out)

def clambu_dec(m, obj, iv='\x00'*16):
    m = b64d(m)
    out = ''.join([r for r in clamburound(m, obj, iv)])
    return out

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", help="encrypt file", action="store_true")
    parser.add_argument("-d", "--decrypt", help="decrypt file", action="store_true")
    parser.add_argument("-i", metavar='in-file', type=argparse.FileType('rb'), help="input file argument")
    parser.add_argument("-o", help="output file argument", action="store", dest='output')
    parser.add_argument("-k", help="key argument", action="store", dest='key')
    parser.add_argument("--iv", help="initialization vector argument", action="store", dest='iv')
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    
    try: args = parser.parse_args()
    except IOError, msg: parser.error(str(msg))

    def fail(msg):
        print msg
        os._exit(1)

    #ensure only one flag for encryption or decryption
    if args.encrypt and args.decrypt: fail("Must select only one flag (-e or -d) for encryption/decryption")

    #input file argument (mandatory)
    try: s = args.i.read()
    except: fail("Must provide input file")

    #output file argument
    if args.output: output = args.output
    else:
        file, ext = os.path.splitext(os.path.basename(args.i.name))
        output = os.path.dirname(args.i.name) + file + "_out" + ext
    try: f = open(output, 'w')
    except: fail("Unable to write to file: " + output)

    #parse key argument
    try: obj = AES.new(args.key)
    except: fail("AES key must be either 16, 24, or 32 bytes long")

    #parse iv argument
    if args.iv:
        if len(args.iv) % 16 == 0: iv = args.iv
        else: fail("Bad IV argument, IV must be exactly 16 bytes")
    else: iv = chr(0) * 16

    #verbose info
    global verbose
    verbose = args.verbose
    if verbose:
        print "Method =\t", "Decrypting" if args.decrypt else "Encrypting"
        print "Input  =\t", args.i.name
        print "Output =\t", output
        print "Key    =\t", strhex(args.key)
        print "IV     =\t", strhex(args.iv)

    out = clambu_dec(s, obj, iv) if args.decrypt else clambu_enc(s, obj, iv)
    if verbose: print "\n" + "-"*20 + "OUTPUT BEGIN" + "-"*20 + "\n" + out +"\n" + "-"*21 + "OUTPUT END" + "-"*21 + "\n"
    f.write(out)

    args.i.close()
    f.close()
    os._exit(1)

if __name__ == '__main__': main()

#example usage:
#./clambu.py -i input.txt -k sixteen_byte_key
#./clambu.py -i --decrypt input.txt -o output.txt -k sixteen_byte_key --iv sixtasn_byse_cat -v