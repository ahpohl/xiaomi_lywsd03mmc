#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 26 11:48:53 2020

@author: alex
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from bluepy.btle import Scanner, DefaultDelegate

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            print("Discovered device", dev.addr)
        elif isNewData:
            print("Received new data from", dev.addr)

if __name__ == '__main__':
#    scanner = Scanner().withDelegate(ScanDelegate())
#    devices = scanner.scan(10.0)
#
#    for dev in devices:
#        print("Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi))
#        for (adtype, desc, value) in dev.getScanData():
#            print("  %s = %s" % (desc, value))
    
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    print(" shared key :",shared_key.hex())
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=64,
                       salt=None,
                       info=b'mible-setup-info',
                       backend=default_backend()).derive(shared_key)
    print("derived key :",derived_key.hex())
    token = derived_key[0:12]
    bind_key = derived_key[12:28]
    A = derived_key[28:44]
    print("      token :", token.hex())
    print("   bind_key :", bind_key.hex())
    print("          A :", A.hex())
    
    aesccm = AESCCM(A)
    nonce = bytearray([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27])
    did = "blt.3.129vl4ap05o01".encode()
    aad = "devID".encode()
    did_ct = aesccm.encrypt(nonce, did, aad)
    print("    AES did :", did_ct.hex())
