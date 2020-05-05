#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 26 15:43:04 2020

@author: alex
"""
import binascii

class BindKey:
    def __init__(self, *parts):
        self.parts = parts

    def __str__(self):
        return ''.join(f'{part:02X}' for part in self.parts)
    
    @property
    def as_raw(self):
        return binascii.a2b_hex(self.__str__())

def bind_key(value):
    parts = [value[i:i+2] for i in range(0, len(value), 2)]
    if len(parts) != 16:
        print("Bind key must consist of 16 hexadecimal numbers")
    parts_int = []
    if any(len(part) != 2 for part in parts):
        print("Bind key must be format XX")
    for part in parts:
        try:
            parts_int.append(int(part, 16))
        except ValueError:
            print("Bind key must be hex values from 00 to FF")

    return BindKey(*parts_int).as_raw

if __name__ == '__main__':
    key = "4e36de30695f9dcc45764f1a6f1a000c"
    validate = bind_key(key)
    print(validate)
    print(len(validate))