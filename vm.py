# Virtual Machine
from functools import reduce
from decimal import *

import opcodes
from log_ import log
from stack import Stack
from instructions import inst_mapping
from constants import MULTIPLIER

class VM:
    def __init__(self, code_=[]):
        self.code = code_
        self.stack = Stack()
        self.memory = {}
        self.pc = 0             # program counter
        self.cache_state = {}
        self.cache_accounts = {}
        self.analysed_code = {}
        self.is_safe = self.check_safety()


    def check_safety(self):
        return isinstance(self.code, list) and len(self.code) > 1
    

    def is_instr_safe(self, instr, elem=None):
        match instr:
            case opcodes.PUSH:
                if elem is None:
                    return False
    
                return True
            case opcodes.ADD:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case opcodes.SUB:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case opcodes.MUL:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case opcodes.DIV:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal) 
            case opcodes.DUP:
                # lowest case in a dup is 1 element needed, hence, stack size of 2
                if self.stack.size() < 2:
                    return False
                
                num = self.stack.peek()
                return self.stack.size()-1 >= num
            case opcodes.STOP:
                return True
            case opcodes.ROOTHASH:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.SHA512:
                # lowest case in a sha512 is 1 element needed, hence, stack size of 2
                if self.stack.size() < 2:
                    return False
                
                num = self.stack.peek()
                return self.stack.size()-1 >= num
            case opcodes.TXHASH:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str) 
            case opcodes.ISZERO:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), Decimal) 
            case opcodes.EQ:
                return self.stack.size() > 1 and ((isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)) or (isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)))
            case opcodes.COLLHASH:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.TXVALSHASH:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)
            case opcodes.STATE:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.UPDATECACHE:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.NOW:
                return True
            case opcodes.SWAP:
                # can swap a decimal with a string
                return self.stack.size() > 1
            case opcodes.CADDR:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)
            case opcodes.DADDR:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.CENTRY:
                first_check = self.stack.size() > 0 and isinstance(self.stack.peek(), str)
                if not first_check:
                    return False
                
                entry_name = self.stack.peek()
                match entry_name:
                    case 'SELL':
                        # TODO also check if the value is a decimal or int, correct order mapping
                        return self.stack.size() >= 8 
                    case 'BUY':
                        return self.stack.size() >= 8
                    case 'DS':
                        return self.stack.size() >= 10
                    case 'EGGS':
                        return self.stack.size() >= 8
                    case 'TRADE':
                        return self.stack.size() >= 8
                    case _:
                        return False
            case opcodes.DENTRY:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)
            case opcodes.PREPFINALISE:
                new_l = [x for x in self.stack.get_stack() if isinstance(x, str)]
                if len(new_l) == 0:
                    return False
                
                return isinstance(reduce(lambda a, b: a and b, new_l), bool)


    def execute(self):
        if not self.is_safe:
            log.error("execution failed, check")
            return None, None, None
        
        while self.pc < len(self.code):
            log.debug(f"Stack dump: {self.stack.get_stack()}")
            val = self.code[self.pc]
            if not self.is_instr_safe(val, elem=self.code[self.pc+1] if self.pc+1 < len(self.code) and val == opcodes.PUSH else None):
                log.error(f"Instruction provided not safe, {val}")
                return None, None, None

            if val == opcodes.PUSH:
                self.stack, self.memory, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val)](self.code[self.pc+1], stack=self.stack, memory=self.memory, pc=self.pc, analysed=self.analysed_code)
            else:
                log.debug(f"Instruction not PUSH, {val}")
                log.debug(f'{self.stack.get_stack()}')
                self.stack, self.memory, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val)](stack=self.stack, memory=self.memory, pc=self.pc, analysed=self.analysed_code)
            
            
            if self.pc == -1:
                # successful completion
                log.info("execution success")
                if self.stack.size():
                    # no update was made to firestore, hence just return computed output
                    return self.stack.pop(), None, None
                
                return None, self.cache_state, self.cache_accounts
            
            if self.stack is None and self.pc is None and self.cache_state is None and self.cache_accounts is None:
                # execution failed
                log.error("execution failed")
                return None, None, None


