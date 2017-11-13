# slice is 2× faster than list looping but is ns only
"""
#The slowest run took 5.98 times longer than the fastest. This could mean that an intermediate result is being cached.
1000000 loops, best of 3: 521 ns per loop
The slowest run took 6.95 times longer than the fastest. This could mean that an intermediate result is being cached.
1000000 loops, best of 3: 324 ns per loop
The slowest run took 7.43 times longer than the fastest. This could mean that an intermediate result is being cached.
1000000 loops, best of 3: 334 ns per loop
"""
row = ["raz", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva", "dva"]
chosen_cols = [8, 9, 10]
def x():
    return [row[i] for i in chosen_cols]
    
def y():
    return row[8:25]
   
def z():
    return row[slice(8,10)]

%timeit x()
%timeit y()
%timeit z()
