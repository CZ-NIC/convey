"""
Accessing by object takes 5/4 more of time than by list.

100 loops, best of 3: 3.99 ms per loop
100 loops, best of 3: 5 ms per loop
"""


class Object:
    def __init__(self, a, b):
        self.a = a
        self.b = b
        
statics = [[r(), r()] for i in range(100000)]
objects = [Object(r(), r()) for i in range(100000)]

def test1():
    for it in statics:
        it[0]
    
def test2():
    for it in objects:
        it.a        
    
%timeit test1()
%timeit test2()
