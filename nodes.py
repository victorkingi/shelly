# NODES

class NumberNode:
    def __init__(self, tok_):
        self.tok = tok_
        self.pos_start = self.tok.pos_start
        self.pos_end = self.tok.pos_end
    

    def __repr__(self):
        return f'{self.tok}'


class BinOpNode:
    def __init__(self, left_node_, op_tok_, right_node_):
        self.left_node = left_node_
        self.op_tok = op_tok_
        self.right_node = right_node_
        self.pos_start = self.left_node.pos_start
        self.pos_end = self.right_node.pos_end

    def __repr__(self):
        return f'({self.left_node}, {self.op_tok}, {self.right_node})'


class UnaryOpNode:
    def __init__(self, op_tok_, node_):
        self.op_tok = op_tok_
        self.node = node_
        self.pos_start = self.op_tok.pos_start
        self.pos_end = self.node.pos_end
    

    def __repr__(self):
        return f'({self.op_tok}, {self.node})'
