import atheris
import sys
import random
from opcodes import Opcodes

total_ops = 29

with atheris.instrument_imports():
    from vm import VM

valid_strings = ['world_state', 'EVENT', 'SHA256', 'PURITY', 'main', '5,6', '', "DEAD", "SICK", "HOUSE", "CAGE", 'SELL', 'TRADE', 'BUY', 'DS', 'EGGS', 'purchases', 'eggs_collected', 'sales', 'dead_sick', 'trades', 'BLACK_HOLE', "THIKAFARMERS", "CAKES", "DUKA", 'OTHER','PURITY', 'FEEDS', 'DRUGS', '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', "LAYERS", "CHICK"]

def CustomMutator(data, max_size, seed):
  fdp = atheris.FuzzedDataProvider(data)
  input_list = fdp.ConsumeIntListInRange(200, 0, total_ops+(len(valid_strings)))
  i = 0
  for x in range(len(input_list)):
    if i+1 < len(input_list):
      if input_list[i] == Opcodes.PUSH.value and input_list[i+1] > total_ops:
        input_list[i+1] = valid_strings[input_list[i+1]-(total_ops+1)]
        i += 2
      elif input_list[i] == Opcodes.PUSH.value:
        i += 2
      elif input_list[i] > total_ops:
        input_list[i] = random.randint(1, total_ops)
        i += 1
      else:
        i += 1
    else:
      if i-1 < len(input_list):
        if isinstance(input_list[i-1], int):
          if input_list[i-1] > total_ops:
            input_list[i-1] = random.randint(1, total_ops)
      break
  
  vm_ = VM(input_list)
  res, state, acc = vm_.execute()
  if res is not None or (state is not None and acc is not None):
    input_list = atheris.Mutate(bytes(input_list), len(input_list))
  else:
    input_list = [0, 4, 0, 5, 5, 0, 5, 0, 3, 6, 5, 0, 5, 7, 28]

  return bytes(input_list)


@atheris.instrument_func
def TestVM(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_list = fdp.ConsumeIntListInRange(200, 0, total_ops+(len(valid_strings)))
  i = 0
  for x in range(len(input_list)):
    if i+1 < len(input_list):
      if input_list[i] == Opcodes.PUSH.value and input_list[i+1] > total_ops:
        input_list[i+1] = valid_strings[input_list[i+1]-(total_ops+1)]
        i += 2
      elif input_list[i] == Opcodes.PUSH.value:
        i += 2
      elif input_list[i] > total_ops:
        input_list[i] = random.randint(1, total_ops)
        i += 1
      else:
        i += 1
    else:
      if i-1 < len(input_list):
        if isinstance(input_list[i-1], int):
          if input_list[i-1] > total_ops:
            input_list[i-1] = random.randint(1, total_ops)
            break
      break

  vm_ = VM(input_list)
  vm_.execute()


atheris.Setup(sys.argv, TestVM, custom_mutator=CustomMutator)
atheris.Fuzz()
