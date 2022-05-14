# NODES

class NumberNode:
    def __init__(self, tok_):
        self.tok = tok_
    

    def __repr__(self):
        return f'{self.tok}'


class BinOpNode:
    def __init__(self, left_node_, op_tok_, right_node_):
        self.left_node = left_node_
        self.op_tok = op_tok_
        self.right_node = right_node_
    

    def __repr__(self):
        return f'({self.left_node}, {self.op_tok}, {self.right_node})'


class UnaryOpNode:
    def __init__(self, op_tok_, node_):
        self.op_tok = op_tok_
        self.node = node_
    

    def __repr__(self):
        return f'({self.op_tok}, {self.node})'
