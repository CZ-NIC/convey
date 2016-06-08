#!/usr/bin/env python3
# It is not a problem if we ask 10^6 times for a dict value (in comparison with static class value).
import timeit

setup = '''
class A:
    foo = "bar"
    d = {"foo":"bar"}
a = A()

def run():
    a.foo

def run2():
    A.foo
    
def run3():
    a.d["foo"]
s = "foo"    
def run4():
    if s in A.d:
        A.d[s]
'''
number = 1000000
print(timeit.timeit("run()",number = number, setup=setup))
print(timeit.timeit("run2()",number = number, setup=setup))
print(timeit.timeit("run3()",number = number, setup=setup))
print(timeit.timeit("run4()",number = number, setup=setup))