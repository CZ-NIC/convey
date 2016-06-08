#!/usr/bin/env python3
# It is at least 100x quicker to check ip in set than loop prefixes all the time.
#
import timeit

setup = '''
import random
from math import floor, ceil
from netaddr import IPNetwork, IPRange
def ra():
    return floor(random.random()*256)

ranges = {}
ipSeen = set()

for i in range(1000):
    s = "{}.{}.{}.{}".format(ra(),ra(),ra(),ra())
    ipSeen.add(s)

for i in range(100): # ranges
    s = "{}.{}.{}.{}".format(ra(),ra(),ra(),ra())
    prefix = IPNetwork(s+"/"+str(ceil(random.random()*24)))
    ranges[prefix] = True

def run():
    for i in range(1000):
        s = "{}.{}.{}.{}".format(ra(),ra(),ra(),ra())    
        s in ipSeen
        
def run2():
    for i in range(1000):    
        s = "{}.{}.{}.{}".format(ra(),ra(),ra(),ra())    
        for prefix, o in ranges.items():
            s in prefix      
'''
timeit.timeit("run2()",number = 1, setup=setup)