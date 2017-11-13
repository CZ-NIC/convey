"""

if I join 4 lambdas, it's 3× slower

The slowest run took 10.30 times longer than the fastest. This could mean that an intermediate result is being cached.
1000000 loops, best of 3: 613 ns per loop
The slowest run took 10.07 times longer than the fastest. This could mean that an intermediate result is being cached.
1000000 loops, best of 3: 205 ns per loop
"""

x = lambda val: val*3
y = lambda val: x(val+1)
z = lambda val: y(val/3)
zz = lambda val: z(val+1)

def test1():
    zz(3)
    
def test2():
    val = 3
    return ((((val+1)/3)+1)*3)    
    
%timeit test1()
%timeit test2()
