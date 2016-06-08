#!/usr/bin/env python3
# Jsonpickle is working great.

import jsonpickle

class Registry:
    def __init__(self):
        self.a = 5

class A:
    def __init__(self):
        self.abusemail = Registry()
        self.csirt = Registry()
        self.regs = [self.abusemail, self.csirt]

        
a = A()        
st=  jsonpickle.encode(a, keys = True)
b = jsonpickle.decode(st, keys=True)
b.csirt.a