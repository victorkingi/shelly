import atheris
import sys


with atheris.instrument_imports():
    from lexer import Lexer, run


def TestLexer(data):
  test1 = data.decode(errors='backslashreplace')
  test2 = data.decode(errors='replace')
  test3 = data.decode(errors='surrogateescape')
  test4 = data.decode(errors='ignore')
  all_inputs = [test1, test2, test3, test4]

  for input_ in all_inputs:
    ast, err, total_lexed = run(fn=input_, text=input_)

    if err is None:
      if len(input_) != total_lexed:
        raise RuntimeError(f"edge case found. Inconsistent lexed characters")

    if ast is None:
      if err is None:
        raise RuntimeError(f"edge case found")


atheris.Setup(sys.argv, TestLexer)
atheris.Fuzz()
