from lexer import run
from compiler import Compiler
from vm import VM
from opcodes import STOP
import sys
from decimal import *
from log_ import fh

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
                compiler_.global_code.append([STOP])
                flattened_code = [item for sublist in compiler_.global_code for item in sublist]
                vm_ = VM(flattened_code)
                res, state, acc = vm_.execute()
                print("vm solution:", res[:10], "other", result.value)
    
    fh.close()
    print("file closed")
