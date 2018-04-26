from collections import defaultdict


class Graph:
    def __init__(self, private_nodes=set()):
        self.nodes = set()
        self.edges = defaultdict(list)
        self.distances = {}
        self.private_nodes = private_nodes

    def add_node(self, value):
        self.nodes.add(value)

    def add_edge(self, to_node, from_node, distance=1):
        self.edges[from_node].append(to_node)
        self.edges[to_node].append(from_node)
        self.add_node(from_node)
        self.add_node(to_node)
        self.distances[(from_node, to_node)] = distance

    def dijkstra(self, target, start=None, ignore_private=False):
        """
        Performs Dijkstra's algorithm and returns
            [start node, ... , target node] (if start specified)
        OR
            {"node": distance to target, ...}

            ignore_private = True - do not return private notes within results (ex. whois)
        """
        visited = {target: 0}
        tree = {}

        nodes = set(self.nodes)

        while nodes:
            min_node = None
            for node in nodes:
                if node in visited:
                    if min_node is None:
                        min_node = node
                    elif visited[node] < visited[min_node]:
                        min_node = node

            if min_node is None:
                break

            nodes.remove(min_node)
            current_weight = visited[min_node]

            for edge in self.edges[min_node]:
                try:
                    weight = current_weight + self.distances[(min_node, edge)]
                    if edge not in visited or weight < visited[edge]:
                        visited[edge] = weight
                        tree[edge] = min_node
                except KeyError:
                    pass

        if start:
            path = [start]
            pivot = start
            i = 0
            while pivot != target:
                i += 1
                pivot = tree[pivot]
                path.append(pivot)

                if i > 10:
                    print("cycles", path, target)
                    break
            return path

        if ignore_private:
            for node in self.private_nodes:
                if node in visited:
                    del visited[node]

        return dict((k, v) for (k, v) in visited.items() if v > 0)  # skip the same node
