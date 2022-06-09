# COMPILER

from decimal import *

from opcodes import Opcodes
from constants import *
from nodes import NumberNode, UnaryOpNode, BinOpNode
from error import NoVisitMethodError, RuntimeError

class Number:
    def __init__(self, value_):
        self.value = Decimal(f'{value_}')
        self.set_pos()
    

    def set_pos(self, pos_start_=None, pos_end_=None):
        self.pos_start = pos_start_
        self.pos_end = pos_end_
        return self
    
    def add(self, b, code):
        if isinstance(b, Number):
            code.append([Opcodes.ADD.value])
            return Number(self.value + b.value), code, None

    
    def sub(self, b, code):
        if isinstance(b, Number):
            code.append([Opcodes.SUB.value])
            return Number(self.value - b.value), code, None
    
    def mul(self, b, code):
        if isinstance(b, Number):
            code.append([Opcodes.MUL.value])
            return Number(self.value * b.value), code, None

    def div(self, b, code):
        if isinstance(b, Number):
            if b.value == 0:
                return None, None, RuntimeError(b.pos_start, b.pos_end, 'Division by zero')

            code.append([Opcodes.DIV.value])
            return Number(self.value / b.value), code, None
    

    def __repr__(self):
        return str(self.value)


class RTResult:
    def __init__(self):
        self.value = None
        self.error = None

    def register(self, res):
        if res.error:
            self.error = res.error
        return res.value
    

    def success(self, value_):
        self.value = value_
        return self
    
    def failure(self, error_):
        self.error = error_
        return self
    

class Compiler:
    def __init__(self):
        self.global_code = []


    def visit(self, node):
        method_name = f'visit_{type(node).__name__}'
        method = getattr(self, method_name, self.no_visit_method)
        return method(node)

    
    def no_visit_method(self, node):
        res = RTResult()
        return res.failure(NoVisitMethodError(node))
    
    def visit_NumberNode(self, node):
        num = Number(node.tok.value).set_pos(node.pos_start, node.pos_end)
        self.global_code.append([Opcodes.PUSH.value, num.value])
        return RTResult().success(num)


    def visit_BinOpNode(self, node):
        res = RTResult()
        
        left = res.register(self.visit(node.left_node))
        if res.error:
            return res
        right = res.register(self.visit(node.right_node))
        if res.error:
            return res

        if node.op_tok.type == TT_PLUS:
            result, code, error = left.add(right, self.global_code)
        elif node.op_tok.type == TT_MINUS:
            result, code, error = left.sub(right, self.global_code)
        elif node.op_tok.type == TT_MUL:
            result, code, error = left.mul(right, self.global_code)
        elif node.op_tok.type == TT_DIV:
            result, code, error = left.div(right, self.global_code)
        
        if error:
            return res.failure(error)

        self.global_code = code

        return res.success(result.set_pos(node.pos_start, node.pos_end))
        

    def visit_UnaryOpNode(self, node):
        res = RTResult()
        num = res.register(self.visit(node.node))
        error = None
        code = self.global_code
        if res.error:
            return res
        
        if node.op_tok.type == TT_MINUS:
            num, code, error = num.mul(Number(-1), self.global_code)
            code.insert(-1, [Opcodes.PUSH.value, Number(-1).value])
        
        if error:
            return res.failure(error)
        else:
            self.global_code = code
            return res.success(num.set_pos(node.pos_start, node.pos_end))


