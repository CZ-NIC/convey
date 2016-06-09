from math import ceil,sqrt
from sys import stdout
class A:
    def __init__(self):
        self.lineCount = 0
        self.lineSout = 1
        self.lineSumCount = 0        
    
    def run(self):
        self.lineCount +=1
        if self.lineCount == self.lineSout:
            self.lineSumCount += 1
            #self.lineSout = ceil(self.lineSumCount + self.lineSumCount * 0.01 * log(self.lineSumCount)) +1
            #self.lineSout = self.lineSumCount + ceil(self.lineSumCount * 0.3 * sqrt(self.lineSumCount))+1
            self.lineSout = self.lineCount + ceil(0.5 * sqrt(self.lineSumCount))
            
            #stdout.write(str(ceil(self.lineSumCount * 0.4 * sqrt(self.lineSumCount)))+ " ")
            
            return True
    
a = A()
l = []
for i in range(10000):
    if a.run():
        l.append(i)
print(" ")
print(l)
print(len(l))