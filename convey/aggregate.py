from typing import Callable, Generator, Union

AggregateMethod = Callable
"A method of the Aggregate class, ex: Aggregate.sum"

class Aggregate:

    def __init__(self, factory: AggregateMethod):
        self.count: Union[int, str] = 0
        "count or description"
        self.generator: Generator = factory()
        next(self.generator)

        self.is_roundable = factory in (Aggregate.sum, Aggregate.avg)
        self.is_too_broad = factory is self.list

    def get(self):
        return round(self.count, 2) if self.is_roundable else self.count

    @classmethod
    def all(cls):
        return [cls.avg, cls.sum, cls.count, cls.min, cls.max, cls.list, cls.set]

    @staticmethod
    def avg():
        count = 0
        res = float((yield))
        while True:
            count += 1
            res += float((yield res / count))

    @staticmethod
    def sum():
        res = 0
        while True:
            res += float((yield res))

    @staticmethod
    def count():
        res = 0
        while True:
            yield res
            res += 1

    @staticmethod
    def min():
        v = yield
        while True:
            v = min((yield v), v)

    @staticmethod
    def max():
        v = yield
        while True:
            v = max((yield v), v)

    @staticmethod
    def list():
        l = []
        while True:
            l.append((yield l))

    @staticmethod
    def set():
        s = set()
        while True:
            s.add((yield s))

    # XX If we would like to serialize a function and this is not possible, we can serialize it ourselves that way:
    # @staticmethod
    # def avg():
    #     count = 0
    #     try:
    #         res = float((yield))
    #     except LoadFromSerialization:
    #         count, res = yield
    #     try:
    #         while True:
    #             count += 1
    #             res += float((yield res / count))
    #     except StopIteration: -> serialization request
    #         yield count, res


aggregate_functions = [f.__name__ for f in Aggregate.all()]
aggregate_functions_str = "".join("\n* " + f for f in aggregate_functions)