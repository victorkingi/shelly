import atheris
import sys
import random
import os
from opcodes import PUSH

with atheris.instrument_imports():
    from vm import VM

valid_strings = ['SELL', 'TRADE', 'BUY', 'DS', 'EGGS', 'purchases', 'eggs_collected', 'sales', 'dead_sick', 'trades']

@atheris.instrument_func
def TestVM(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  max_size = random.randint(0, 100)
  input_list = fdp.ConsumeIntListInRange(max_size, 0, 30)
  rand_list = []
  for i in range(int(len(input_list)/2)):
    n = random.randint(0, len(input_list)-1)
    rand_list.append(n)
  
  
  for x in rand_list:
    if input_list[x-1] == PUSH:
      input_list[x] = valid_strings[random.randint(0, len(valid_strings)-1)]

  vm_ = VM(input_list)
  vm_.execute()


atheris.Setup(sys.argv, TestVM)
atheris.Fuzz()
