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
                if not isinstance(num, Decimal):
                    return False

                return self.stack.size()-1 >= int(num)
            case opcodes.STOP:
                return True
            case opcodes.ROOTHASH:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.SHA512:
                # lowest case in a sha512 is 1 element needed, hence, stack size of 2
                if self.stack.size() < 2:
                    return False
                
                num = self.stack.peek()
                if not isinstance(num, Decimal):
                    return False
                
                return self.stack.size()-1 >= int(num) and int(num) > 0 
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
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), Decimal)
            case opcodes.DADDR:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.CENTRY:
                first_check = self.stack.size() > 0 and isinstance(self.stack.peek(), str)
                if not first_check:
                    log.debug("entry name not string")
                    return False
                
                entry_name = self.stack.peek()
                match entry_name:
                    case 'SELL':
                        if self.stack.size() >= 9:
                            values = self.stack.peek_n(9)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'tray_no', 'tray_price', 'buyer', 'date', 'section' ]
                            values.reverse()
                            values.pop(0) # we don't need entry_name
                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal))
                            bool_list.append(isinstance(values[4], Decimal))
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal))
                            bool_list.append(isinstance(values[7], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            return isinstance(res, bool) and res

                        log.debug(f"stack size not 9 or greater but {self.stack.size()}")
                        return False
                    case 'BUY':
                        if self.stack.size() >= 9:
                            values = self.stack.peek_n(9)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'item_no', 'item_price', 'item_name', 'date', 'section' ]
                            values.reverse()
                            values.pop(0) # we don't need entry_name
                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal))
                            bool_list.append(isinstance(values[4], Decimal))
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal))
                            bool_list.append(isinstance(values[7], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            return isinstance(res, bool) and res

                        log.debug(f"stack size not 9 or greater but {self.stack.size()}")
                        return False
                    case 'DS':
                        if self.stack.size() >= 11:
                            values = self.stack.peek_n(11)
                            # [ 'entry_name', 'submitted_on', 'by', 'image_url', 'image_id', 'reason', 'tx_hash', 'number', 'date', 'section', 'location']
                            values.reverse()
                            values.pop(0) # we don't need entry_name
                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str))
                            bool_list.append(isinstance(values[4], str))
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal))
                            bool_list.append(isinstance(values[7], Decimal))
                            bool_list.append(isinstance(values[8], str))
                            bool_list.append(isinstance(values[9], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            return isinstance(res, bool) and res

                        log.debug(f"stack size not 11 or greater but {self.stack.size()}")
                        return False
                    case 'EGGS':
                        if self.stack.size() >= 14:
                            values = self.stack.peek_n(14)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'a1', 'a2', 'b1', 'b2', 'c1', 'c2', 'broken', 'house', 'date', 'trays_collected']
                            values.reverse()
                            values.pop(0) # we don't need entry_name
                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal))
                            bool_list.append(isinstance(values[4], Decimal))
                            bool_list.append(isinstance(values[5], Decimal))
                            bool_list.append(isinstance(values[6], Decimal))
                            bool_list.append(isinstance(values[7], Decimal))
                            bool_list.append(isinstance(values[8], Decimal))
                            bool_list.append(isinstance(values[9], Decimal))
                            bool_list.append(isinstance(values[10], Decimal))
                            bool_list.append(isinstance(values[11], Decimal))
                            bool_list.append(isinstance(values[12], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            return isinstance(res, bool) and res

                        log.debug(f"stack size not 14 or greater but {self.stack.size()}")
                        return False
                    case 'TRADE':
                        if self.stack.size() >= 10:
                            values = self.stack.peek_n(10)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'from', 'to', 'purchase_hash', 'sale_hash', 'amount', 'date']
                            values.reverse()
                            values.pop(0) # we don't need entry_name
                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str))
                            bool_list.append(isinstance(values[4], str))
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], str))
                            bool_list.append(isinstance(values[7], Decimal))
                            bool_list.append(isinstance(values[8], Decimal))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            return isinstance(res, bool) and res

                        log.debug(f"stack size not 9 or greater but {self.stack.size()}")
                        return False
                    case _:
                        return False
            case opcodes.DENTRY:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)
            case opcodes.PREPFINALISE:
                new_l = [x for x in self.stack.get_stack() if isinstance(x, str)]
                if len(new_l) == 0:
                    return False
                
                res = reduce(lambda a, b: a and b, new_l)
                return isinstance(res, bool) and res


    def execute(self):
        log.debug(f"Code input: {self.code}")

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
                self.stack, self.memory, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val)](stack=self.stack, memory=self.memory, pc=self.pc, analysed=self.analysed_code)
            
            
            if self.pc == -1:
                # successful completion
                if self.stack.size():
                    # no update was made to firestore, hence just return computed output
                    log.info(f"execution success, result: {self.stack.peek()}")
                    return self.stack.pop(), None, None

                log.info(f"execution success, cache_state: {self.cache_state}, accounts: {self.cache_accounts}")
                return None, self.cache_state, self.cache_accounts
            
            if self.stack is None and self.pc is None and self.cache_state is None and self.cache_accounts is None:
                # execution failed
                log.error("execution failed")
                return None, None, None
        
        log.error("Unclean exit, no STOP opcode")
        return None, None, None

