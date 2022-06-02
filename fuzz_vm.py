import atheris
import sys
import random

with atheris.instrument_imports():
    from vm import VM


@atheris.instrument_func
def TestVM(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_list = fdp.ConsumeIntListInRange(20, 0, 30)
  
  print("list:", input_list)
  vm_ = VM(input_list)
  res, state, acc = vm_.execute()
  print("vm solution:", res)


atheris.Setup(sys.argv, TestVM)
atheris.Fuzz()
