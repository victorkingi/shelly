from lexer import run
from compiler import Compiler
from vm import VM
import sys

if __name__ == '__main__':
    while True:
        text = input('basic > ')
        ast, error, _ = run('<stdin>', str(2**549976986543))

        if error:
            print(error.as_string())
        else:
            compiler_ = Compiler()
            result = compiler_.visit(ast)
            if result.error:
                print(result.error.as_string())
            else:
                vm_ = VM(compiler_.global_code)
                vm_.execute()
                print(vm_.pop(), result.value)
        
        

