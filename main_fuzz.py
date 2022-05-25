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
  ans = Decimal('nan')

  try:
    ans = eval(input_)
    ans = Decimal(f'{ans}')
    ans = ans.quantize(TWOPLACES)
  except (OverflowError, SyntaxError, TypeError, ZeroDivisionError, ValueError, NameError, AttributeError, InvalidOperation, MemoryError) as e:
    pass

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

        if final_ans.is_nan() and ans.is_nan():
          raise RuntimeError(f"Invalid evaluation, got {final_ans}, expected {ans}")


        if state is not None or acc is not None:
          raise RuntimeError(f"Invalid evaluation, state or account were not none, {state}, {acc}")
  

  except RecursionError as e:
    pass
      


atheris.Setup(sys.argv, TestLexer)
atheris.Fuzz()
