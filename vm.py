# Virtual Machine
from stack import Stack
from instructions import inst_mapping
from opcodes import *

class VM:
    def __init__(self, code_):
        self.code = code_
        self.stack = Stack()
        self.pc = -1             # program counter
        self.analysed_code = {}
        self.analysed_code['VALID_JUMPDEST'] = []
        self.analysed_code['VALID_JUMPIF'] = []
        self.analyse()

    def analyse(self):
        i = 0
        for val in self.code:
            self.analysed_code[str(i)] = val
            i += 1
        
        for key, val in self.analysed_code.items():
            if val == JUMPDEST:
                self.analysed_code['VALID_JUMPDEST'].append(key)
            elif val == JUMPIF:
                self.analysed_code['VALID_JUMPIF'].append(key)
        
        if len(self.analysed_code['VALID_JUMPIF']) != len(self.analysed_code['VALID_JUMPDEST']):
            raise RuntimeError("jump array length not equal to jump dest")

    
    def execute(self):
        while self.pc < len(self.code):
            val = self.analysed_code[str(self.pc)]

            if len(val) < 2:
                # print("before1", self.stack.get_stack())
                self.stack, self.pc = inst_mapping[val[0]](self.stack, pc=self.pc, analysed=self.analysed_code)
                # print("after1", self.stack.get_stack())
            else:
                # print("before2", self.stack.get_stack())
                self.stack, self.pc = inst_mapping[val[0]](self.stack, val[1], pc=self.pc, analysed=self.analysed_code)
                # print("after2", self.stack.get_stack())
            
            if self.pc == -1:
                # successful completion
                print("execution success")
                return None
            
            if self.stack is None and self.pc is None:
                # execution failed
                print("execution failed")
                return None
    
