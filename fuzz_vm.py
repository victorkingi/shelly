import atheris
import sys
import random
import os
import re
import opcodes
from constants import *

with atheris.instrument_imports():
    from vm import VM

valid_strings = ['world_state', 'EVENT', 'SHA256', 'PURITY', 'main', '5,6', '', "DEAD", "SICK", "HOUSE", "CAGE", 'SELL', 'TRADE', 'BUY', 'DS', 'EGGS', 'purchases', 'eggs_collected', 'sales', 'dead_sick', 'trades', 'BLACK_HOLE', "THIKAFARMERS", "CAKES", "DUKA", 'OTHER','PURITY', 'FEEDS', 'DRUGS', '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', "LAYERS", "CHICK"]

def is_instr_safe(instr=None, elem=None, stack=None, cache_state=None, cache_accounts=None):
        match instr:
            case opcodes.PUSH:
                if elem is None:
                    return False
    
                return True
            case opcodes.ADD:
                return stack.size() > 1 and isinstance(stack.peek(), Decimal) and isinstance(stack.peek2(), Decimal)
            case opcodes.SUB:
                return stack.size() > 1 and isinstance(stack.peek(), Decimal) and isinstance(stack.peek2(), Decimal)
            case opcodes.MUL:
                return stack.size() > 1 and isinstance(stack.peek(), Decimal) and isinstance(stack.peek2(), Decimal)
            case opcodes.DIV:
                return stack.size() > 1 and isinstance(stack.peek(), Decimal) and isinstance(stack.peek2(), Decimal) 
            case opcodes.DUP:
                # lowest case in a dup is 1 element needed, hence, stack size of 2
                if stack.size() < 2:
                    return False
                
                num = stack.peek()
                if not isinstance(num, Decimal):
                    return False

                return stack.size()-1 >= int(num)
            case opcodes.STOP:
                return True
            case opcodes.ROOTHASH:
                return stack.size() > 0 and isinstance(stack.peek(), str) and stack.peek() in EVENTC.values()
            case opcodes.SHA256:
                # lowest case in a sha512 is 1 element needed, hence, stack size of 2
                if stack.size() < 2:
                    return False
                
                num = stack.peek()
                if not isinstance(num, Decimal):
                    return False
                
                return stack.size()-1 >= int(num) and int(num) > 0 
            case opcodes.ISZERO:
                return stack.size() > 0 and isinstance(stack.peek(), Decimal) 
            case opcodes.EQ:
                return stack.size() > 1 and ((isinstance(stack.peek(), str) and isinstance(stack.peek2(), str)) or (isinstance(stack.peek(), Decimal) and isinstance(stack.peek2(), Decimal)))
            case opcodes.STATE:
                return stack.size() > 0 and isinstance(stack.peek(), str) and stack.peek() in EVENTC.values()
            case opcodes.UPDATECACHE:
                is_valid = stack.size() > 0 and isinstance(stack.peek(), str) and (stack.peek() in EVENTC.values() or stack.peek() == 'world_state')
                if is_valid:
                    if stack.peek() in cache_state and stack.peek() != 'world_state':
                        ids = set(cache_state[stack.peek()].keys())
                        return 'prev_states' in ids and 'state' in ids
                    elif stack.peek() == 'world_state':
                        return True
                return False
            case opcodes.NOW:
                return True
            case opcodes.SWAP:
                # can swap a decimal with a string
                return stack.size() > 1
            case opcodes.CADDR:
                return stack.size() > 0 and isinstance(stack.peek(), str)
            case opcodes.DADDR:
                return stack.size() > 0 and isinstance(stack.peek(), str)
            case opcodes.CENTRY:
                first_check = stack.size() > 0 and isinstance(stack.peek(), str)
                if not first_check:
                    
                    return False
                
                entry_name = stack.peek()
                match entry_name:
                    case 'SELL':
                        if stack.size() >= 9:
                            values = stack.peek_n(9)
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
                            
                            
                            res = reduce(lambda a, b: a and b, bool_list)
                            
                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    
                                    return False
                                
                                # check if valid section
                                if values[7] not in VALID_SELL_SECTIONS:
                                    
                                    return False
                                
                                # check if valid buyer
                                if values[5] not in VALID_BUYERS and values[7] == "OTHER":
                                    
                                    return False
                                
                                if values[7] in ["THIKAFARMERS", "CAKES", "DUKA"] and values[5] != values[7]:
                                    for idx, x in enumerate(stack.get_stack()):
                                        if x == values[5]:
                                            stack.replace(idx, values[7])
                                            
                                            break

                                return True
                            else:
                                
                                return False

                        
                        return False
                    case 'BUY':
                        if stack.size() >= 9:
                            values = stack.peek_n(9)
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
                            
                            
                            res = reduce(lambda a, b: a and b, bool_list)

                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    
                                    return False
                                
                                # check if valid section
                                if values[7] not in VALID_BUY_SECTIONS:
                                    
                                    return False
                                
                                if values[7] == "FEEDS" and values[5] not in ["LAYERS", "CHICK"]:
                                    
                                    return False
                                
                                if values[7] in ["PURITY"]:
                                    for idx, x in enumerate(stack.get_stack()):
                                        if x == values[5]:
                                            stack.replace(idx, values[7])
                                            
                                            break
                                
                                return True
                            else: 
                                return False
                        return False
                    case 'DS':
                        if stack.size() >= 11:
                            values = stack.peek_n(11)
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
                            
                            
                            res = reduce(lambda a, b: a and b, bool_list)

                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[5]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    
                                    return False
                                
                                if values[8] not in ["DEAD", "SICK"]:
                                    
                                    return False

                                if values[9] not in ["HOUSE", "CAGE"]:
                                    
                                    return False
                                return True
                            else:
                                return False
                        return False
                    case 'EGGS':
                        if stack.size() >= 14:
                            values = stack.peek_n(14)
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
                            
                            
                            res = reduce(lambda a, b: a and b, bool_list)

                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    
                                    return False

                                return True
                            else:
                                
                                return False

                        
                        return False
                    case 'TRADE':
                        if stack.size() >= 10:
                            values = stack.peek_n(10)
                            # [ 'entry_name', 'submitted_on', 'by', 'tx_hash', 'from', 'to', 'purchase_hash', 'sale_hash', 'amount', 'date']
                            values.reverse()
                            values.pop(0) # we don't need entry_name

                            bool_list = []
                            bool_list.append(isinstance(values[0], Decimal)  and values[0] >= 0)
                            bool_list.append(isinstance(values[1], str))
                            bool_list.append(isinstance(values[2], str))
                            bool_list.append(isinstance(values[3], str) and not not cache_accounts.get(values[3], 0)) # from
                            bool_list.append(isinstance(values[4], str) and not not values[4]) # to
                            bool_list.append(isinstance(values[5], str))
                            bool_list.append(isinstance(values[6], str))
                            bool_list.append(isinstance(values[7], Decimal)  and values[7] > 0)
                            bool_list.append(isinstance(values[8], Decimal)  and values[8] >= 0)

                            if isinstance(values[5], str) and isinstance(values[6], str) and values[5] and values[6]:
                                
                                return False
                            
                            
                            res = reduce(lambda a, b: a and b, bool_list)
                            if isinstance(res, bool) and res:
                                # check if valid hash
                                to_check_hash = values[2]
                                is_valid_hash = re.search("^[a-f0-9]{64}$", to_check_hash)

                                if not is_valid_hash:
                                    
                                    return False
                                 
                                return True
                            else:
                                
                                return False

                        
                        return False
                    case _:
                        return False
            case opcodes.DENTRY:
                return stack.size() > 1 and isinstance(stack.peek(), str) and isinstance(stack.peek2(), str) and stack.peek2() in EVENTC.values()
            case opcodes.PREPFINALISE:
                new_l = [x for x in stack.get_stack() if isinstance(x, str)]
                if len(new_l) == 0:
                    return False
                
                res = reduce(lambda a, b: a and b, new_l)
                return isinstance(res, bool) and res
            case opcodes.CALCSTATE:
                return stack.size() > 0 and isinstance(stack.peek(), str) and stack.peek() in EVENTC.values()
            case opcodes.MSTORE:
                return stack.size() > 0
            case opcodes.MLOAD:
                return stack.size() > 0
            case opcodes.LT:
               return stack.size() > 1 and type(stack.peek()) == type(stack.peek2())
            case opcodes.GT:
               return stack.size() > 1 and type(stack.peek()) == type(stack.peek2())
            case opcodes.PANIC:
                return stack.size() > 0 and isinstance(stack.peek(), Decimal)
            case opcodes.BALANCE:
                return stack.size() > 0 and isinstance(stack.peek(), str)
            case opcodes.CALCROOTHASH:
                return stack.size() > 0 and isinstance(stack.peek(), str) and stack.peek() in EVENTC.values()
            case opcodes.UPROOTHASH:
                if stack.size() > 0 and isinstance(stack.peek(), str):
                    is_valid_hash = re.search("^[a-f0-9]{64}$", stack.peek())

                    if not is_valid_hash:
                        
                        return False

                    return stack.size() > 1 and isinstance(stack.peek2(), str) and (stack.peek2() in EVENTC.values() or stack.peek2() == 'main')
            case opcodes.CALCMAINSTATE:
                total_earned_exists = ['total_earned' in v for k in cache_state for _k, v in cache_state[k].items() if EVENTC[SELL] == k and 'state' == _k]
                total_spent_exists = ['total_spent' in v for k in cache_state for _k, v in cache_state[k].items() if EVENTC[BUY] == k and 'state' == _k]
                total_birds_exists = ['total_birds' in v for k in cache_state for _k, v in cache_state[k].items() if 'world_state' == k and 'main' == _k]
                is_len_valid = len(total_earned_exists) == len(total_spent_exists) == len(total_birds_exists) == 1
                return is_len_valid and total_earned_exists[0] and total_spent_exists[0] and total_birds_exists[0]
            case _:
                
                return False


def CustomMutator(data, max_size, seed):
  fdp = atheris.FuzzedDataProvider(data)
  input_list = fdp.ConsumeIntListInRange(30, 0, 30+(len(valid_strings)))

  vm_ = VM(input_list)
  val = True
  if vm_.is_safe:
    i = 0
    for idx in range(len(input_list)):
      if i >= len(input_list):
        break
      if input_list[i] == opcodes.PUSH:
        if i+1 < len(input_list):
          val = val and is_instr_safe(instr=input_list[i], elem=input_list[i+1] if input_list[i+1] <= 30 else valid_strings[input_list[i+1]-31], stack=vm_.stack, cache_state=vm_.cache_state, cache_accounts=vm_.cache_accounts)
          i += 2
        else:
          val = False
          break
      else:
        val = val and is_instr_safe(input_list[i], stack=vm_.stack, cache_state=vm_.cache_state, cache_accounts=vm_.cache_accounts)
        i += 1

      if not val:
        break
    
  if val:
    input_list = input_list+[opcodes.STOP]
    input_list = atheris.Mutate(bytes(input_list), len(input_list))
  return bytes(input_list)


@atheris.instrument_func
def TestVM(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_list = fdp.ConsumeIntListInRange(30, 0, 30+(len(valid_strings)))

  for x in range(len(input_list)):
    if input_list[x] > 30:
      input_list[x] = valid_strings[input_list[x]-31]

  vm_ = VM(input_list)
  vm_.execute()


atheris.Setup(sys.argv, TestVM, custom_mutator=CustomMutator)
atheris.Fuzz()
