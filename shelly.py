from lexer import run
from compiler import Compiler
from vm import VM
import sys
from decimal import *
from log_ import fh
from common_opcodes import *
from util import map_nested_dicts_modify
from test_data import create_instr
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
                sell = [26, 'OTHER', 26, 0, 26, 'KAMAU', 26, 1, 26, 253, 26, '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', 26, 'dfgh', 26, 0, 26, 'SELL', 14]
                buy = [26, 'PURITY', 26, 0, 26, 'dfgs', 26, 1, 26, 253, 26, '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', 26, 'dfgh', 26, 0, 26, 'BUY', 14]
                eggs = [26, '32,21',26, 1,26, 1,26, 1,26, 1,26, 1,26, 1,26, 1, 26, 1, 26, 25, 26, '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', 26, 'dfgh', 26, 0, 26, 'EGGS', 14]
                trade = [26, 45, 26, 654, 26, '',26, '',26, 'hfdg', 26, 'BLACK_HOLE', 26, '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', 26, 'dfgh', 26, 0, 26, 'TRADE', 14]
                ds = [26, 'gfsd', 26, 'dfgs', 26, 1, 26, 253, 26, '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9',26, 'dfgh',26, 'dfgh',26, 'https://google.com', 26, 'dfgh', 26, 0, 26, 'DS', 14]
                end = [0, 'eggs_collected', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+[0, 'trades', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26, 0, 'purchases', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+[0, 'sales', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26, 27, 14, 0, 'main', 2, 26, 31]
                vm_ = VM(create_instr('eggs_collected')+create_instr('sales')+create_instr('purchases')+[0, 'trades', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+create_instr('trade')+create_instr('ds')+[0, 'dead_sick', 0, 1, 1, 0, 1, 1, 24, 25, 14, 26]+end)
                cops = CommonOps()
                #vm_ = VM(cops.create_ds_instructions())
                # 1647291600 1640034000
                vm_.analyse()
                res, state, acc = vm_.execute()
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
