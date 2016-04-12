#!/usr/bin/env python
import ctypes
from ctypes import *

clib = ctypes.cdll.LoadLibrary('./test.so')

strhex = lambda s: " ".join("{:02x}".format(ord(c)) for c in s)

xorstr = lambda x, y: ''.join([chr(ord(x[i]) ^ ord(y[i])) for i in range(len(x))])

#xorbyt(b1,b2,l): xor b1 with b2
def xorbyt(b1=bytearray("asdfasdf"), b2=bytearray("fdsafdsa"), l=8):
    for i in range(l): b1[i] = b1[i] ^ b2[i]


xorblock = clib.xorblock
#xorblock.restype = c_char_p
#xorblock.argtypes = [c_char_p, c_char_p]

def cxor(x,y):
	print strhex(x.value), strhex(y.value)
	#x = cast(x, POINTER(c_char))
	xorblock(x, y)
	print strhex(x.value), strhex(y.value)
	

def cxor1(x,y):
	print sizeof(x), repr(x.raw), sizeof(y), repr(y.raw)
	out = xorblock(x, y)
	print strhex(out)

#http://www.dreamincode.net/forums/topic/252650-making-importing-and-using-a-c-library-in-python-linux-version/
@profile
def main():
    
    for i in range(10):
        # Note, this uses the Python 2 print 
        print "Random = %d" % clib.get_random(1, 10)

    clib.helloworld()
    clib.myprint("testomg")
    print("testomg")

    xorstr("asdfasdf","fdsafdsa")
    xorbyt()
    xorblock(c_char_p("asdfasdf"), c_char_p("fdsafdsa"))

    #x,y = c_char_p("asdfasdf"), c_char_p("fdsafdsa")
    #cxor(x,y)

if __name__ == '__main__':
    main()
