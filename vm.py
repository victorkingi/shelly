# Virtual Machine
from py_data_structure import Stack
from instructions import inst_mapping
from opcodes import *

class VM:
    def __init__(self, code_):
        self.code = code_
        self.stack = Stack()

    
    def execute(self):
        for val in self.code:
            if len(val) < 2:
                # print("before1", self.stack.get_stack())
                self.stack = inst_mapping[str(val[0])](self.stack)
                # print("after1", self.stack.get_stack())
            else:
                # print("before2", self.stack.get_stack())
                self.stack = inst_mapping[str(val[0])](self.stack, val[1])
                # print("after2", self.stack.get_stack())

    
    def get(self):
        return self.stack.get_stack()
    
    def is_stack_empty(self):
        return self.stack.isEmpty()
    
    def get_stack_size(self):
        return self.stack.size()
    
    def pop(self):
        elem = self.stack.top()
        self.stack.pop()
        return elem
            

