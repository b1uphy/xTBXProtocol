#!/usr/bin/python
# -*- coding: utf8 -*-
'''
contact:
bluphy@qq.com
@author: bluphy
Created on 2018-06-07 18:38 by xw
This is a tbox internal communication protocol library.
'''
xDEBUG = True

def splittbxmsg(buf):
    if buf[:2] != b'\x0d\x05': 
        return (None,buf)
    else:
        length = buf[4]
        msg = buf[:length+8]
        return (msg,buf[length+8:])


def calCKS(data:bytes):
    sum = data[0]
    for x in data[1:]:
        sum = sum^x
    return sum.to_bytes(1,'big',signed=False)


def parsetbxprotocol(raw:bytes)->tuple:
    '''
        return (dom:int,cmd:int,length:int,data:bytes,cks:int,errorstr:str)
    '''
    if raw[:2] != b'\x0d\x05': 
        return (None,None)    
    else:      
        dom = raw[2]
        cmd = raw[3]
        length = raw[4]
        data = raw[5:5+length]
        cks = raw[5+length]
        if cks != int.from_bytes(calCKS(data),'big',signed=False):
            errorstr = 'CKS error'
            if xDEBUG:
                print('ERROR:CKS error')
        else:
            errorstr = ''
        return (dom,cmd,length,data,cks,errorstr)

def createtbxprotocolmsg(dom:bytes,cmd:bytes,length:int,data:bytes):
    return b''.join([b'\x0d\x05',dom,cmd,length.to_bytes(1,'big',signed=False),data,calCKS(data),b'\x0d\x0a'])

if __name__=='__main__':
    longstream = bytes.fromhex('0d0531330701020304050607000d0a')+b'\r\x0513\x05xxxxxx\r\n'
    msg,bufleft = splittbxmsg(longstream)
    print('msg:',msg.hex())
    print('bufleft:',bufleft.hex())

    badcksmsg = bytes.fromhex('0d0531330701020304050607000d0a')
    print('bad:',parsetbxprotocol(badcksmsg))

    goodcksmsg = b'\r\x0513\x05xxxxxx\r\n'
    print('good:',parsetbxprotocol(goodcksmsg))

    dom = b'1'
    cmd = b'2'
    length = 6
    def cdata(l):
        e = b'0'
        d = b''
        for i in range(l):
            d+=i.to_bytes(1,'big',signed=False)
        return d

    data = cdata(length)
    cks = calCKS(data)

    print('cks',cks.hex())

    print(createtbxprotocolmsg(dom,cmd,length,data))
    
