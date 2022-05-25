# Virtual Machine
from stack import Stack
from instructions import inst_mapping
from opcodes import *
from constants import MULTIPLIER

class VM:
    def __init__(self, code_):
        self.code = code_
        self.stack = Stack()
        self.pc = 0             # program counter
        self.analysed_code = {}
        self.analysed_code['VALID_JUMPIF'] = []
        self.cache_state = {}
        self.cache_accounts = {}
        self.total_mul_ops = 0
        self.total_div_ops = 0
        self.analyse()

    def analyse(self):
        i = 0

        for val in self.code:
            self.analysed_code[str(i)] = val
            i += 1
            if val[0] == MUL:
                self.total_mul_ops += 1
            elif val[0] == DIV:
                self.total_div_ops += 1
        
        
        for key in self.analysed_code:
            if len(self.analysed_code[key]) != 0:
                if self.analysed_code[key][0] == JUMPIF:
                    self.analysed_code['VALID_JUMPIF'].append(key)
        
        

    
    def execute(self):
        while self.pc < len(self.code):
            val = self.analysed_code[str(self.pc)]
            #print(val)
            #print("Stack", self.stack.get_stack())

            if len(val) < 2:
                self.stack, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val[0])](self.stack, pc=self.pc, analysed=self.analysed_code)
            else:
                self.stack, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val[0])](self.stack, val[1], pc=self.pc, analysed=self.analysed_code)
            
            if self.pc == -1:
                # successful completion
                #print("execution success")
                if self.stack.size():
                    # no update was made to firestore, hence just return computed output
                    return self.stack.pop(), None, None
                
                return None, self.cache_state, self.cache_accounts
            
            if self.stack is None and self.pc is None and self.cache_state is None and self.cache_accounts is None:
                # execution failed
                #print("execution failed")
                return None, None, None
    
