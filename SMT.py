import hashlib
from bisect import bisect_left, bisect_right
from queue import PriorityQueue


class SMT:
    def __init__(self, hash_function=hashlib.sha256, presence_data='1', absence_data='0', debug=False):
        self.hash_function = hash_function
        self.digest_size = hash_function().digest_size * 8

        self.debug = debug

        self.presence_data = presence_data.encode('ascii')
        self.absence_data = absence_data.encode('ascii')

        self.leafs_map = {}
        self.sorted_keys = PriorityQueue()

        self.mask_cache = {(self.digest_size - 1): (1 << self.digest_size) - 1}

        self.defaults_cache = {(self.digest_size - 1): self.absence_data}

        for depth in range(self.digest_size - 2, -1, -1):
            self.defaults_cache[depth] = \
                self.hash_function(
                    self.defaults_cache[depth + 1] + self.defaults_cache[depth + 1]
                ).hexdigest().encode('ascii')

            self.mask_cache[depth] = self.get_mask(depth)

    def add(self, e):
        element_hash = self.hash_function(e.encode('ascii')).digest()
        element_int = int.from_bytes(element_hash, byteorder='big', signed=False)
        self.leafs_map[element_int] = self.presence_data

        self.sorted_keys.put(element_int)

        if self.debug:
            print('Inserting element {0}. Value: {1:0x}'.format(e, element_int))

    def bisect_lt(self, x):
        i = bisect_left(self.sorted_keys.queue, x)
        return i

    def bisect_gt(self, x):
        i = bisect_right(self.sorted_keys.queue, x)
        return i

    def is_default_node(self, path: int, depth: int):
        start_value = path & self.mask_cache[depth]
        end_value = path | ((2 << (self.digest_size - depth - 1)) - 1)

        init_index = self.bisect_lt(start_value)
        final_index = self.bisect_gt(end_value)

        return init_index == final_index

    def get_mask(self, depth):
        return ((1 << depth) - 1) << (self.digest_size - depth)

    def get_leaf(self, path):
        return self.leafs_map.get(path, self.absence_data)

    def build_subtree(self, path, depth, non_standard_nodes, on_path=True, save=True):
        if depth == self.digest_size:
            if save and self.get_leaf(path) != self.absence_data:
                non_standard_nodes[depth] = self.get_leaf(path)

            return self.get_leaf(path)

        if self.is_default_node(path, depth):
            return self.defaults_cache[depth]

        this_hash = self.hash_function(
            self.build_subtree(path, depth + 1, non_standard_nodes, on_path, on_path) +
            self.build_subtree(path ^ (2 ** (self.digest_size - depth - 1)), depth + 1, non_standard_nodes, False,
                               on_path)
        ).hexdigest().encode('ascii')

        if save and not on_path and depth > 0:
            non_standard_nodes[depth] = this_hash

        if self.debug:
            print(self.format_path(path, depth), on_path, save, non_standard_nodes)

        return this_hash

    def format_path(self, path, depth):
        return ('{0:0' + str(depth) + 'b}').format(path)[0:depth] + '-' * (self.digest_size - depth)

    def build_proof(self, path):
        non_standard_nodes = {}
        merkle_root = self.build_subtree(path, 0, non_standard_nodes)

        return merkle_root, non_standard_nodes
