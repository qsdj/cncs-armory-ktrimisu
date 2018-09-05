#!/usr/bin/env python3
# coding:utf-8
'''
写 whatweb plugins会用到md5值
'''
import sys
import hashlib                    
                                  
def md5sum(filename):
    '''
    get filename md5
    '''            
    with open(filename,"rb") as fd:
        fcont = fd.read()
        fmd5 = hashlib.md5(fcont)
    return fmd5               
                                  
if __name__ == "__main__":
    try:       
        print(md5sum(sys.argv[1]).hexdigest())
    except:
        print("example: python3 {} filename".format(sys.argv[0]))