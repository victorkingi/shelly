import atheris
import sys


with atheris.instrument_imports():
    from lexer import Lexer, run


def TestRandomBytesLexer(data):
  test1 = data.decode(errors='backslashreplace')
  test2 = data.decode(errors='replace')
  test3 = data.decode(errors='surrogateescape')
  test4 = data.decode(errors='ignore')
  all_inputs = [test1, test2, test3, test4]

  for input_ in all_inputs:
    ast, err = run(input_)

    # tokens should never be empty if error is empty
    # also tokens should never have an element if error is not empty
    if ast is None:
      if error is None:
        raise RuntimeError(f"edge case found, input: {input_}")
    else:
      if error is not None:
        raise RuntimeError(f"edge case found, tokens: {tokens}, error: {error.as_string()}, input: {input_}")


def clean_input(str_data):
  operations = ['+', '-', '/', '*']
  parentheses = ['(', ')']
  digits = '0123456789'
  dot = '.'
  for val in str_data:
    if val not in digits and val not in parentheses and val not in operations and val not in dot:
      return False
  
  return True


def TestValidInputLexer(data):
  data = data.decode(encoding='ascii', errors='ignore')
  isValid = clean_input(data)
  if not isValid:
    return
  
  ast, err = run(data)

  # tokens should never be empty if error is empty
  # also tokens should never have an element if error is not empty
  if ast is None:
    if error is None:
      raise RuntimeError(f"edge case found, input: {input_}")
  else:
    if error is not None:
      raise RuntimeError(f"edge case found, tokens: {tokens}, error: {error.as_string()}, input: {input_}")


atheris.Setup(sys.argv, TestValidInputLexer)
# atheris.Setup(sys.argv, TestRandomBytesLexer)
atheris.Fuzz()
