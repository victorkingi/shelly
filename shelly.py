from lexer import run
from compiler import Compiler
from vm import VM
import sys
from decimal import *
from log_ import fh
from common_opcodes import *


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
                vm_ = VM([0, 4, 0, 5, 5, 0, 5, 0, 3, 6, 5, 0, 5, 7, 28])
                res, state, acc = vm_.execute()
                print("vm result:", res)
    
    fh.close()
    print("file closed")
