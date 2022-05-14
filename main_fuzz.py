import atheris
import sys


with atheris.instrument_imports():
    from lexer import Lexer, run
    from compiler import Compiler
    from vm import VM


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
    
    if not err:
      compiler_ = Compiler()
      result = compiler_.visit(ast)

      if not result.error:
        vm_ = VM(compiler_.global_code)
        vm_.execute()
        if vm_.get_stack_size() != 1:
          raise RuntimeError("Stack size not 1")
        
        try:
          ans = eval(input_)
          if ans != result.value.value or ans != vm_.pop():
            raise RuntimeError(f"Invalid evaluation, got {result.value.value}, {vm_.pop()} expected {ans}")
        except (SyntaxError, TypeError, ZeroDivisionError) as e:
          pass
          
        if result.error and result.value:
          raise RuntimeError(f"edge case found, value and result same")
        if result is None:
          raise RuntimeError(f"edge case found, none result")
      

atheris.Setup(sys.argv, TestLexer)
atheris.Fuzz()
