import atheris
import sys


with atheris.instrument_imports():
    from lexer import Lexer, run
    from compiler import Compiler
    from vm import VM


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
          vm_ = VM(compiler_.global_code)
          vm_.execute()
          final_ans = vm_.pop()

          ans = eval(input_)
          if ans != final_ans:
            raise RuntimeError(f"Invalid evaluation, got {final_ans}, expected {ans}")

  except (SyntaxError, TypeError, ZeroDivisionError, RecursionError) as e:
    pass
      


atheris.Setup(sys.argv, TestLexer)
atheris.Fuzz()
