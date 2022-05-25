import atheris
import sys
from decimal import *

getcontext().traps[FloatOperation] = True
TWOPLACES = Decimal(10) ** -2 


with atheris.instrument_imports():
    from lexer import Lexer, run
    from compiler import Compiler
    from vm import VM
    from opcodes import STOP


def TestLexer(data):
  input_ = data.decode(errors='ignore')

  try:
    ast, error, total_lexed = run(fn=input_, text=input_)

    if not error:
      if total_lexed != len(input_):
        raise RuntimeError(f"edge case found, got {total_lexed}, expected {len(input_)}, {error}, {ast}")

      compiler_ = Compiler()
      result = compiler_.visit(ast)
      
      if not result.error:
        compiler_.global_code.append([STOP])
        vm_ = VM(compiler_.global_code)
        final_ans, state, acc = vm_.execute()

        if final_ans.is_nan():
          raise RuntimeError(f"Invalid evaluation, got NaN")


        if state is not None or acc is not None:
          raise RuntimeError(f"Invalid evaluation, state or account were not none, {state}, {acc}")

  except RecursionError:
    pass
      


atheris.Setup(sys.argv, TestLexer)
atheris.Fuzz()
