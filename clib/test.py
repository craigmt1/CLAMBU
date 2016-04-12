#!/usr/bin/env python

import ctypes

#http://www.dreamincode.net/forums/topic/252650-making-importing-and-using-a-c-library-in-python-linux-version/

def main():
    my_test_lib = ctypes.cdll.LoadLibrary('./test.so')
    aeslib = ctypes.cdll.LoadLibrary('./aes.so')
    for i in range(10):
        # Note, this uses the Python 2 print 
        print "Random = %d" % my_test_lib.get_random(1, 10)
    my_test_lib.helloworld()

if __name__ == '__main__':
    main()
