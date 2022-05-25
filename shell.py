from lexer import run
from compiler import Compiler
from vm import VM
from opcodes import STOP
import sys
from decimal import *

if __name__ == '__main__':
    while True:
        text = input('basic > ')
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
                print(compiler_.global_code)
                vm_ = VM(compiler_.global_code)
                res, state, acc = vm_.execute()
                print("vm solution:", res, "other", result.value)
        
        

