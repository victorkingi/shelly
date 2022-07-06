from lexer import run
from compiler import Compiler
from vm import VM
import sys
from decimal import *
from log_ import fh
from common_opcodes import *
from util_ import map_nested_dicts_modify
from instructions import test
import json


if __name__ == '__main__':
    while True:
        text = input('basic > ')
        if text == ':q':
            break
        ast, error, total = run('<stdin>', text)

        if error:
            print(error.as_string())
        else:
            compiler_ = Compiler()
            result = compiler_.visit(ast)

            if result.error:
                print(result.error.as_string())
            else:
                compiler_.global_code.append([Opcodes.STOP.value])
                flattened_code = [item for sublist in compiler_.global_code for item in sublist]
                end = [0, 'dead_sick', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+[0, 'eggs_collected', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+[0, 'trades', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26, 0, 'purchases', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+[0, 'sales', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26, 27, 14, 0, 'main', 2, 26, 31]
                start = [0, 'sales', 0, 'purchases', 0, 'trades', 0, 'eggs_collected', 0, 'dead_sick', 0, 'world_state', 20, 20, 20, 20, 20, 20]
                signal = -2
                res, acc, state = None, None, None
                retries = 0
                while signal == -2:
                    vm_ = VM(start+end[:-1]+[37, 38, 39, 40, 31])
                    vm_.analyse()
                    res, state, acc, signal = vm_.execute()
                    if signal == -2:
                        print("re-run signal received!")
                        retries += 1
                        if retries > 4:
                            print("exceeded maximum rerun attempts of", retries)
                            break
                    
                print("vm result:", res)
                if state is not None and acc is not None:
                    map_nested_dicts_modify(state, lambda v: float(v) if isinstance(v, Decimal) else v)
                    map_nested_dicts_modify(acc, lambda v: float(v) if isinstance(v, Decimal) else v)
                    with open("state.json", "w") as outfile:
                        json.dump(state, outfile)
                    with open("accounts.json", "w") as outfile:
                        json.dump(acc, outfile)
                    print("execution success")

    
    fh.close()
    print("file closed")
