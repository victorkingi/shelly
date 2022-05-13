import atheris
import sys


with atheris.instrument_imports():
    from lexer import Lexer, run_lexer


def TestRandomBytesLexer(data):
  try:
    test1 = data.decode(errors='backslashreplace')
    test2 = data.decode(errors='replace')
    test3 = data.decode(errors='surrogateescape')
    test4 = data.decode(errors='ignore')
    all_inputs = [test1, test2, test3, test4]

    for input_ in all_inputs:
      lexer = Lexer(input_)
      tokens, error = lexer.make_tokens()

      # tokens should never be empty if error is empty
      # also tokens should never have an element if error is not empty
      if not tokens:
        if error is None:
          raise RuntimeError(f"edge case found, input: {input_}")
      else:
        if error is not None:
          raise RuntimeError(f"edge case found, tokens: {tokens}, error: {error.as_string()}, input: {input_}")
  except IndexError:
    pass


def TestValidInputLexer(data):
  try:
    data = data.decode(encoding='ascii', errors='ignore')
    tokens, error = run_lexer(data)

    # tokens should never be empty if error is empty
    # also tokens should never have an element if error is not empty
    if not tokens:
      if error is None:
        raise RuntimeError(f"edge case found, input: {input_}")
    else:
      if error is not None:
        raise RuntimeError(f"edge case found, tokens: {tokens}, error: {error.as_string()}, input: {input_}")
  except IndexError:
    pass


# atheris.Setup(sys.argv, TestValidInputLexer)
atheris.Setup(sys.argv, TestRandomBytesLexer)
atheris.Fuzz()
