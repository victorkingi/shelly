# Virtual Machine
from functools import reduce
from decimal import *
import re
import os
import time
import uuid

from opcodes import Opcodes
from log_ import log
from stack import Stack
from instructions import inst_mapping
from constants import *

EARLIEST_VALID_YEAR = 1577836800 # unix epoch of earliest reasonable data date which is 1st january midnight 2020


class VM:
    def __init__(self, code_=[]):
        self.instance_id = uuid.uuid4()
        self.code = code_
        self.log_file = 'vm.log'
        self.stack = Stack()
        self.memory = {'PROCID': self.instance_id, 'TOTALCREATES': 0, 'TOTALDELETES': 0, 'TOTALREPLACE': 0, 'REPLACED': {}, 'ADDED': {}, 'DELETES': {}}
        self.pc = 0             # program counter
        self.cache_state = {}
        self.cache_accounts = {}
        self.analysed_code = {}
        self.is_safe = self.check_safety()


    def check_safety(self):
        return isinstance(self.code, list) and len(self.code) > 0
    

    def analyse(self):
        jumpif_list = []
        jumpdest_list = []
        k = 0
        for _ in self.code:
            if k >= len(self.code):
                break
            if self.code[k] == Opcodes.JUMPIF.value:
                jumpif_list.append(k)
            elif self.code[k] == Opcodes.JUMPDEST.value:
                jumpdest_list.append(k)

            if self.code[k] == Opcodes.PUSH.value:
                k += 2
            else:
                k += 1
        if len(jumpif_list) != len(jumpdest_list):
            log.warning("Analysing jump instructions failed")
            return
        
        self.analysed_code = {str(jumpif_list[i]): jumpdest_list[i] for i in range(len(jumpif_list))}


    def is_instr_safe(self, instr, elem=None):
        match instr:
            case Opcodes.PUSH.value:
                if elem is None:
                    return False
    
                return True
            case Opcodes.POP.value:
                return self.stack.size() > 0
            case Opcodes.ADD.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case Opcodes.SUB.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case Opcodes.MUL.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case Opcodes.DIV.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal) 
            case Opcodes.DUP.value:
                # lowest case in a dup is 1 element needed, hence, stack size of 2
                if self.stack.size() < 2:
                    return False
                
                num = self.stack.peek()
                if not isinstance(num, Decimal):
                    return False

                return self.stack.size()-1 >= int(num)
            case Opcodes.STOP.value:
                return True
            case Opcodes.ROOTHASH.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case Opcodes.SHA256.value:
                if self.stack.size() > 0:
                    num = self.stack.peek()
                    if not isinstance(num, Decimal):
                        return False
                    
                    return self.stack.size()-1 >= int(num) and int(num) >= 0
                
                return False
            case Opcodes.ISZERO.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), Decimal) 
            case Opcodes.EQ.value:
                return self.stack.size() > 1 and ((isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str)) or (isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)))
            case Opcodes.STATE.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case Opcodes.UPDATECACHE.value:
                is_valid = self.stack.size() > 0 and isinstance(self.stack.peek(), str) and (self.stack.peek() in EVENTC.values() or self.stack.peek() == 'world_state')
                if is_valid:
                    if self.stack.peek() in self.cache_state and self.stack.peek() != 'world_state':
                        ids = set(self.cache_state[self.stack.peek()].keys())
                        return 'prev_states' in ids and 'state' in ids
                    elif self.stack.peek() == 'world_state':
                        return True
                return False
            case Opcodes.NOW.value:
                return True
            case Opcodes.INCRBAL.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), Decimal) and self.stack.peek() in self.cache_accounts
            case Opcodes.DECRBAL.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), Decimal) and self.stack.peek() in self.cache_accounts
            case Opcodes.SWAP.value:
                # can swap a decimal with a string
                return self.stack.size() > 1
            case Opcodes.CADDR.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case Opcodes.DADDR.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in self.cache_accounts
            case Opcodes.CENTRY.value:
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
                            bool_list.append(isinstance(values[0], Decimal) and values[0] >= EARLIEST_VALID_YEAR and values[0] <= Decimal(f'{time.time()}'))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal) and values[3] > 0)
                            bool_list.append(isinstance(values[4], Decimal) and values[4] > 0)
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal) and values[6] >= EARLIEST_VALID_YEAR and values[6] <= Decimal(f'{time.time()}'))
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
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= EARLIEST_VALID_YEAR and values[0] <= Decimal(f'{time.time()}'))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal)  and values[3] > 0)
                            bool_list.append(isinstance(values[4], Decimal)  and values[4] > 0)
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal)  and values[6] >= EARLIEST_VALID_YEAR and values[6] <= Decimal(f'{time.time()}'))
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
                                
                                if values[7] in ["PPURITY"]:
                                    is_valid_month = re.search("^([A-Z]{3},)+$", values[5])

                                    if not is_valid_month:
                                        log.warning(f"Invalid payment months for Purity provided, {values[5]}")
                                        return False

                                    if 'paid_purity_last_month' in self.cache_state[EVENTC[BUY]]['state']:
                                        is_valid_last_month = re.search("^[A-Z]{3}$", self.cache_state[EVENTC[BUY]]['state']['paid_purity_last_month'])
                                        if is_valid_last_month:
                                            months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC' ]
                                            my_months = []
                                            entered_months = values[5].split(',')[:-1] # i.e. ['JUN', 'JUL', 'AUG']
                                            last_month = self.cache_state[EVENTC[BUY]]['state']['paid_purity_last_month']
                                            is_entered_safe = [x for x in entered_months if x in months]
                                            if is_entered_safe != entered_months:
                                                log.error(f"Entered months not safe, got {is_entered_safe} from {entered_months}")
                                                return False
                                            is_first_safe = entered_months[0] == months[(months.index(last_month)+1)]

                                            if is_first_safe:
                                                for i, x in enumerate(entered_months):
                                                    if i == 0:
                                                        my_months.append(months.index(x))
                                                    else:
                                                        expected = months[(my_months[-1]+1)]
                                                        if expected != x:
                                                            log.error(f"Invalid month ordering for paid purity got, {x} but wanted {expected}")
                                                            return False
                                                        my_months.append(months.index(x))
                                                log.debug(f"entered paid purity months {entered_months}")
                                            else:
                                                log.error(f"first entry month not correct, {entered_months[0]} expected {months[(months.index(last_month)+1)%len(months)]}")
                                                return False
                                        else:
                                            log.error(f"regex eval failed, string {self.cache_state[EVENTC[BUY]]['state']['paid_purity_last_month']}")
                                            return False             
                                    else:
                                        log.error("Paid purity field does not exist")
                                        return False
                                
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
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= EARLIEST_VALID_YEAR and values[0] <= Decimal(f'{time.time()}'))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str))
                            bool_list.append(isinstance(values[4], str))
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], Decimal)  and values[6] > 0)
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] >= EARLIEST_VALID_YEAR and values[7] <= Decimal(f'{time.time()}'))
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
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= EARLIEST_VALID_YEAR and values[0] <= Decimal(f'{time.time()}'))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], Decimal)  and values[3] > 0 and values[3] <= 75)
                            bool_list.append(isinstance(values[4], Decimal)  and values[4] > 0 and values[4] <= 75)
                            bool_list.append(isinstance(values[5], Decimal)  and values[5] > 0 and values[5] <= 75)
                            bool_list.append(isinstance(values[6], Decimal)  and values[6] > 0 and values[6] <= 75)
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] > 0 and values[7] <= 75)
                            bool_list.append(isinstance(values[8], Decimal)  and values[8] > 0 and values[8] <= 75)
                            bool_list.append(isinstance(values[9], Decimal)  and values[9] >= 0)
                            bool_list.append(isinstance(values[10], Decimal)  and values[10] >= 0)
                            bool_list.append(isinstance(values[11], Decimal)  and values[11] >= EARLIEST_VALID_YEAR and values[11] <= Decimal(f'{time.time()}'))
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
                        if self.stack.size() >= 11:
                            values = self.stack.peek_n(11)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'from', 'to', 'purchase_hash', 'sale_hash', 'amount', 'date', 'reason']
                            values.reverse()
                            values.pop(0) # we don't need entry_name

                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= EARLIEST_VALID_YEAR and values[0] <= Decimal(f'{time.time()}'))
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str) and (not not self.cache_state[EVENTC[TRADE]]['state']['balances'].get(values[3], 0) if 'balances' in self.cache_state[EVENTC[TRADE]]['state'] else False)) # from
                            bool_list.append(isinstance(values[4], str) and not not values[4]) # to
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], str))
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] > 0)
                            bool_list.append(isinstance(values[8], Decimal)  and values[8] >= EARLIEST_VALID_YEAR and values[8] <= Decimal(f'{time.time()}'))
                            bool_list.append(isinstance(values[9], str))

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

                        log.warning(f"stack size not 11 or greater but {self.stack.size()}")
                        return False
                    case _:
                        return False
            case Opcodes.DENTRY.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), str) and isinstance(self.stack.peek2(), str) and self.stack.peek2() in EVENTC.values() and self.stack.peek() in self.cache_state[self.stack.peek2()]
            case Opcodes.PREPFINALISE.value:
                new_l = [x for x in self.stack.get_stack() if isinstance(x, str)]
                if len(new_l) == 0:
                    return False
                
                res = reduce(lambda a, b: a and b, new_l)
                return isinstance(res, bool) and res
            case Opcodes.CALCSTATE.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case Opcodes.MSTORE.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case Opcodes.MLOAD.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in self.memory
            case Opcodes.LT.value:
               return self.stack.size() > 1 and type(self.stack.peek()) == type(self.stack.peek2())
            case Opcodes.GT.value:
               return self.stack.size() > 1 and type(self.stack.peek()) == type(self.stack.peek2())
            case Opcodes.PANIC.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), Decimal)
            case Opcodes.BALANCE.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str)
            case Opcodes.CALCROOTHASH.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), str) and self.stack.peek() in EVENTC.values()
            case Opcodes.UPROOTHASH.value:
                if self.stack.size() > 0 and isinstance(self.stack.peek(), str):
                    is_valid_hash = re.search("^[a-f0-9]{64}$", self.stack.peek())

                    if not is_valid_hash:
                        log.warning(f"Invalid hash provided for root hash, {self.stack.peek()}")
                        return False
                    
                    if 'col_roots' not in self.cache_state['world_state']['main']:
                        log.warning("col_roots not present in world state main")
                        return False

                    return self.stack.size() > 1 and isinstance(self.stack.peek2(), str) and (self.stack.peek2() in EVENTC.values() or self.stack.peek2() == 'main')
                return False
            case Opcodes.CALCMAINSTATE.value:
                total_earned_exists = ['total_earned' in v for k in self.cache_state for _k, v in self.cache_state[k].items() if EVENTC[SELL] == k and 'state' == _k]
                total_spent_exists = ['total_spent' in v for k in self.cache_state for _k, v in self.cache_state[k].items() if EVENTC[BUY] == k and 'state' == _k]
                total_birds_exists = ['total_birds' in v for k in self.cache_state for _k, v in self.cache_state[k].items() if 'world_state' == k and 'main' == _k]
                is_len_valid = len(total_earned_exists) == len(total_spent_exists) == len(total_birds_exists) == 1
                return is_len_valid and total_earned_exists[0] and total_spent_exists[0] and total_birds_exists[0] and 'total_dead' in self.cache_state['dead_sick']['state'] and 'BANK' in self.cache_state['trades']['state']['balances']
            case Opcodes.JUMPIF.value:
                return self.stack.size() > 0 and isinstance(self.stack.peek(), Decimal)
            case Opcodes.JUMPDEST.value:
                return True
            case Opcodes.LAYINGPERCENT.value:
                if self.stack.size() > 1:
                    if isinstance(self.stack.peek2(), str):
                        if self.stack.peek2() in ["WEEK", "MONTH"] and isinstance(self.stack.peek(), Decimal) and 'week_trays_and_exact' in self.cache_state['eggs_collected']['state'] and 'month_trays_and_exact' in self.cache_state['eggs_collected']['state']:
                            return True

                return False
            case Opcodes.TRAYSAVAIL.value:
                return self.stack.size() > 1 and isinstance(self.stack.peek(), Decimal) and isinstance(self.stack.peek2(), Decimal)
            case Opcodes.UIENTRIES.value:
                if all (k in self.cache_state for k in EVENTC.values()) and ('all_hashes' in self.cache_state['world_state']['main'] if 'world_state' in self.cache_state else False):
                    return True
                return False
            case Opcodes.VERIFYCOL.value:
                if all (k in self.cache_state for k in EVENTC.values()):
                    return True
                return False
            case Opcodes.DASHBOARD.value:
                if all (k in self.cache_state for k in EVENTC.values()) and 'trays_available' in self.cache_state['world_state']['main']:
                    return True
                return False
            case Opcodes.WRITE.value:
                return 'root' in self.cache_state['world_state']['main'] if 'world_state' in self.cache_state else False
            case _:
                log.warning(f"Invalid opcode provided, {instr}")
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
        log.info(f"Instance id: {str(self.instance_id)}")
        log.info(f"Code size: {len(self.code)}")
        message = f"Code input: {self.code}"
        message = message[:MAX_CHAR_COUNT_LOG]+"..."  if len(message) > MAX_CHAR_COUNT_LOG else message
        log.debug(message)

        if not self.is_safe:
            log.error("execution failed, check")
            return None, None, None, None
        
        while self.pc < len(self.code):
            message = f"Stack dump: {self.stack.get_stack()}"
            message = message[:MAX_CHAR_COUNT_LOG]+"..."  if len(message) > MAX_CHAR_COUNT_LOG else message
            log.debug(message)
            val = self.code[self.pc]

            if not self.is_instr_safe(val, elem=self.code[self.pc+1] if self.pc+1 < len(self.code) and val == Opcodes.PUSH.value else None):
                res = [name for name, member in Opcodes.__members__.items() if member.value == val]
                log.error(f"Instruction provided not safe, {val}: {res[0] if len(res) > 0 else res}")
                return None, None, None, None

            if val == Opcodes.PUSH.value:
                self.stack, self.memory, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val)](self.code[self.pc+1], stack=self.stack, memory=self.memory, pc=self.pc, analysed=self.analysed_code)
            else:
                self.stack, self.memory, self.pc, self.cache_state, self.cache_accounts = inst_mapping[str(val)](stack=self.stack, memory=self.memory, pc=self.pc, analysed=self.analysed_code)
            
            if self.pc == -2:
                # re-run signal
                return None, None, None, -2
            
            if self.pc == -1:
                # successful completion

                # reset log with unneccessary data
                self.clear_log()

                if self.stack.size():
                    # no update was made to firestore, hence just return computed output
                    log.info(f"execution success, result: {self.stack.peek()}")
                    return self.stack.pop(), None, None, 0

                log.info(f"execution success, replaced {self.memory['TOTALREPLACE']}, created {self.memory['TOTALCREATES']}, deleted {self.memory['TOTALDELETES']} entries")
                for c in self.memory['ADDED']:
                    log.info(f"collection: {c} added {self.memory['ADDED'][c]} entries")

                for c in self.memory['REPLACED']:
                    log.info(f"collection: {c} entries replaced {self.memory['REPLACED'][c]['num']}")
                    log.info(f"hashes of replaced entries: {[x[:5] for x in self.memory['REPLACED'][c]['hashes']]}")
                
                return None, self.cache_state, self.cache_accounts, 0
            
            if self.stack is None and self.pc is None and self.cache_state is None and self.cache_accounts is None:
                # execution failed
                log.error("execution failed")
                return None, None, None, 0
        
        log.error("Unclean exit, no STOP opcode")
        return None, None, None, 0

