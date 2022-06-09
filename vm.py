# Virtual Machine
from functools import reduce
from decimal import *
import re
import sys
import os

import opcodes
from log_ import log
from stack import Stack
from instructions import inst_mapping
from constants import *


class VM:
    def __init__(self, code_=[]):
        self.code = code_
        self.log_file = 'vm.log'
        self.stack = Stack()
        self.memory = {}
        self.pc = 0             # program counter
        self.cache_state = {
            'world_state': {
                'main': {},
                'prev_states': {}
            },
            'sales': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '1': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '2': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }}
                },
                'prev_states': {}
            },
            'purchases': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '1': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '2': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }}
                },
                'prev_states': {}
            },
            'eggs_collected': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '1': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '2': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }}
                },
                'prev_states': {}
            },
            'dead_sick': {
            'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '1': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '2': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }}
                },
                'prev_states': {}
            },
            'trades': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '1': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }, '2': {
                        'op': '',
                        'tx_hash': '',
                        'submitted_on': {'unix': 0, 'locale': ''}
                    }}
                },
                'prev_states': {}
            }
        }
        self.cache_accounts = {'BLACK_HOLE': Decimal(MAX_EMAX) } # main money supplier
        self.analysed_code = {}
        self.is_safe = self.check_safety()


    def check_safety(self):
        return isinstance(self.code, list) and len(self.code) > 0
    

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
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case opcodes.SHA256:
                # lowest case in a sha512 is 1 element needed, hence, stack size of 2
                if self.stack.size() < 2:
                    return False
                
                num = self.stack.peek()
                if not isinstance(num, Decimal):
                    return False
                
                return self.stack.size()-1 >= int(num) and int(num) > 0 
            case opcodes.ISZERO:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), Decimal) 
            case opcodes.EQ:
                return self.stack.size() > 1 and ((isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)) or (isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)))
            case opcodes.STATE:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case opcodes.UPDATECACHE:
                is_valid = self.stack.size() > 0 and isinstance(self.stack.peek(), str) and (self.stack.peek() in EVENTC.values() or self.stack.peek() == 'world_state')
                if is_valid:
                    if self.stack.peek() in self.cache_state and self.stack.peek() != 'world_state':
                        ids = set(self.cache_state[self.stack.peek()].keys())
                        return 'prev_states' in ids and 'state' in ids
                    elif self.stack.peek() == 'world_state':
                        return True
                return False
            case opcodes.NOW:
                return True
            case opcodes.SWAP:
                # can swap a decimal with a string
                return self.stack.size() > 1
            case opcodes.CADDR:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.DADDR:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in self.cache_accounts
            case opcodes.CENTRY:
                first_check = self.stack.size() > 0 and isinstance(self.stack.peek(), str)
                if not first_check:
                    log.warning(f"stack size is 0: {self.stack.size()} or entry name is not a string")
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
                            bool_list.append(isinstance(values[0], Decimal) and values[0] >= 0)
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal) and values[3] > 0)
                            bool_list.append(isinstance(values[4], Decimal) and values[4] > 0)
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal) and values[6] >= 0)
                            bool_list.append(isinstance(values[7], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            
                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    log.warning(f"Invalid hash provided, {to_check_hash}")
                                    return False
                                
                                # check if valid section
                                if values[7] not in VALID_SELL_SECTIONS:
                                    log.warning(f"Invalid section provided, {values[7]}")
                                    return False
                                
                                # check if valid buyer
                                if values[5] not in VALID_BUYERS and values[7] == "OTHER":
                                    log.warning(f"Invalid buyer name provided, {values[5]}")
                                    return False
                                
                                if values[7] in ["THIKAFARMERS", "CAKES", "DUKA"] and values[5] != values[7]:
                                    for idx, x in enumerate(self.stack.get_stack()):
                                        if x == values[5]:
                                            self.stack.replace(idx, values[7])
                                            log.warning(f"Buyer name updated to, {values[7]}")
                                            break

                                return True
                            else:
                                log.warning(f"reduced bool list not True but {res} of type {type(res)}")
                                return False

                        log.warning(f"stack size not 9 or greater but {self.stack.size()}")
                        return False
                    case 'BUY':
                        if self.stack.size() >= 9:
                            values = self.stack.peek_n(9)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'item_no', 'item_price', 'item_name', 'date', 'section' ]
                            values.reverse()
                            values.pop(0) # we don't need entry_name

                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= 0)
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal)  and values[3] > 0)
                            bool_list.append(isinstance(values[4], Decimal)  and values[4] > 0)
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal)  and values[6] >= 0)
                            bool_list.append(isinstance(values[7], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)

                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    log.warning(f"Invalid hash provided, {to_check_hash}")
                                    return False
                                
                                # check if valid section
                                if values[7] not in VALID_BUY_SECTIONS:
                                    log.warning(f"Invalid section provided, {values[7]}")
                                    return False
                                
                                if values[7] == "FEEDS" and values[5] not in ["LAYERS", "CHICK"]:
                                    log.warning(f"Invalid feeds item provided, {values[5]}")
                                    return False
                                
                                if values[7] in ["PURITY"]:
                                    for idx, x in enumerate(self.stack.get_stack()):
                                        if x == values[5]:
                                            self.stack.replace(idx, values[7])
                                            log.warning(f"Item name updated to, {values[7]}")
                                            break
                                
                                return True
                            else:
                                log.warning(f"reduced bool list not True but {res} of type {type(res)}")
                                return False

                        log.warning(f"stack size not 9 or greater but {self.stack.size()}")
                        return False
                    case 'DS':
                        if self.stack.size() >= 11:
                            values = self.stack.peek_n(11)
                            # [ 'entry_name', 'submitted_on', 'by', 'image_url', 'image_id', 'reason', 'tx_hash', 'number', 'date', 'section', 'location']
                            values.reverse()
                            values.pop(0) # we don't need entry_name
                            
                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= 0)
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str))
                            bool_list.append(isinstance(values[4], str))
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal)  and values[6] > 0)
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] >= 0)
                            bool_list.append(isinstance(values[8], str))
                            bool_list.append(isinstance(values[9], str))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)

                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[5]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    log.warning(f"Invalid hash provided, {to_check_hash}")
                                    return False
                                
                                if values[8] not in ["DEAD", "SICK"]:
                                    log.warning(f"Invalid section provided for dead sick entry, {values[8]}")
                                    return False

                                if values[9] not in ["HOUSE", "CAGE"]:
                                    log.warning(f"Invalid location provided for dead sick entry, {values[9]}")
                                    return False

                                return True
                            else:
                                log.warning(f"reduced bool list not True but {res} of type {type(res)}")
                                return False

                        log.warning(f"stack size not 11 or greater but {self.stack.size()}")
                        return False
                    case 'EGGS':
                        if self.stack.size() >= 14:
                            values = self.stack.peek_n(14)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'a1', 'a2', 'b1', 'b2', 'c1', 'c2', 'broken', 'house', 'date', 'trays_collected']
                            values.reverse()
                            values.pop(0) # we don't need entry_name

                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= 0)
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal)  and values[3] > 0 and values[3] <= 75)
                            bool_list.append(isinstance(values[4], Decimal)  and values[4] > 0 and values[4] <= 75)
                            bool_list.append(isinstance(values[5], Decimal)  and values[5] > 0 and values[5] <= 75)
                            bool_list.append(isinstance(values[6], Decimal)  and values[6] > 0 and values[6] <= 75)
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] > 0 and values[7] <= 75)
                            bool_list.append(isinstance(values[8], Decimal)  and values[8] > 0 and values[8] <= 75)
                            bool_list.append(isinstance(values[9], Decimal)  and values[9] > 0)
                            bool_list.append(isinstance(values[10], Decimal)  and values[10] > 0)
                            bool_list.append(isinstance(values[11], Decimal)  and values[11] >= 0)
                            bool_list.append(isinstance(values[12], str) and not not re.search("^[\d]+,([0-9]|1[0-9]|2[0-9])$", values[12]))
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)

                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    log.warning(f"Invalid hash provided, {to_check_hash}")
                                    return False

                                return True
                            else:
                                log.warning(f"reduced bool list not True but {res} of type {type(res)}")
                                return False

                        log.warning(f"stack size not 14 or greater but {self.stack.size()}")
                        return False
                    case 'TRADE':
                        if self.stack.size() >= 10:
                            values = self.stack.peek_n(10)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'from', 'to', 'purchase_hash', 'sale_hash', 'amount', 'date']
                            values.reverse()
                            values.pop(0) # we don't need entry_name

                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= 0)
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str) and not not self.cache_accounts.get(values[3], 0)) # from
                            bool_list.append(isinstance(values[4], str) and not not values[4]) # to
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], str))
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] > 0)
                            bool_list.append(isinstance(values[8], Decimal)  and values[8] >= 0)

                            if isinstance(values[5], str) and isinstance(values[6], str) and values[5] and values[6]:
                                log.warning(f"sale hash and purchase hash not empty, contains, purchase hash: {values[5]}, sale hash: {values[6]}")
                                return False
                            
                            log.debug(f"bool type list: {bool_list}")
                            res = reduce(lambda a, b: a and b, bool_list)
                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    log.warning(f"Invalid hash provided, {to_check_hash}")
                                    return False
                                 
                                return True
                            else:
                                log.warning(f"reduced bool list not True but {res} of type {type(res)}")
                                return False

                        log.warning(f"stack size not 10 or greater but {self.stack.size()}")
                        return False
                    case _:
                        return False
            case opcodes.DENTRY:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str) and self.stack.peek2() in EVENTC.values()
            case opcodes.PREPFINALISE:
                new_l = [x for x in self.stack.get_stack() if isinstance(x, str)]
                if len(new_l) == 0:
                    return False
                
                res = reduce(lambda a, b: a and b, new_l)
                return isinstance(res, bool) and res
            case opcodes.CALCSTATE:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case opcodes.MSTORE:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.MLOAD:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in self.memory
            case opcodes.LT:
               return self.stack.size() > 1 and type(self.stack.peek()) == type(self.stack.peek2())
            case opcodes.GT:
               return self.stack.size() > 1 and type(self.stack.peek()) == type(self.stack.peek2())
            case opcodes.PANIC:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), Decimal)
            case opcodes.BALANCE:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case opcodes.CALCROOTHASH:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case opcodes.UPROOTHASH:
                if self.stack.size() > 0 and isinstance(self.stack.peek(), str):
                    is_valid_hash = re.search("^[a-f0-9]{64}$", self.stack.peek())

                    if not is_valid_hash:
                        log.warning(f"Invalid hash provided for root hash, {self.stack.peek()}")
                        return False

                    return self.stack.size() > 1 and isinstance(self.stack.peek2(), str) and (self.stack.peek2() in EVENTC.values() or self.stack.peek2() == 'main')
            case opcodes.CALCMAINSTATE:
                total_earned_exists = ['total_earned' in v for k in self.cache_state for _k, v in self.cache_state[k].items() if EVENTC[SELL] == k and 'state' == _k]
                total_spent_exists = ['total_spent' in v for k in self.cache_state for _k, v in self.cache_state[k].items() if EVENTC[BUY] == k and 'state' == _k]
                total_birds_exists = ['total_birds' in v for k in self.cache_state for _k, v in self.cache_state[k].items() if 'world_state' == k and 'main' == _k]
                is_len_valid = len(total_earned_exists) == len(total_spent_exists) == len(total_birds_exists) == 1
                return is_len_valid and total_earned_exists[0] and total_spent_exists[0] and total_birds_exists[0]
            case _:
                log.warning("Invalid opcode provided")
                return False

    # silently clears log
    def clear_log(self):
        file_ = self.log_file

        if os.path.exists(file_):
            lookup = 'VM-execution: execution success'
            last_suc = -1

            with open(file_) as myFile:
                for num, line in enumerate(myFile, 1):
                    if lookup in line:
                        last_suc = num

            size = os.path.getsize(file_)
            if last_suc == -1:
                return 0

            if size/(1024 * 1024) > 10:
                log.info(f"found line {last_suc} proceeding with clearing...")
                lines = []
                with open(file_, 'r') as fp:
                    lines = fp.readlines()

                with open(file_, 'w') as fp:
                    for number, line in enumerate(lines):
                        if number >= last_suc-1:
                            fp.write(line)
                
                log.info(f'Reduced file size from {round(size/(1024 * 1024), 2)} MB to {round(os.path.getsize(file_)/(1024 * 1024), 2)} MB')
               

    def execute(self):
        log.info(f"Code input: {self.code}")

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

                # reset log with unneccessary data
                self.clear_log()

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

