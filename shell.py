from lexer import Lexer

def run_lexer(text):
    lexer = Lexer(text)
    return lexer.make_tokens()


if __name__ == '__main__':
    p = bytearray(b'')
    try:
        str_produced = p.decode()
        print("OK", str_produced)
    except:
        pass
    else:
        str_produced = '1+1'
        print("ER", str_produced)


    while True:
        text = input('basic > ')
        result, error = run_lexer(b'\n'.decode(errors='surrogateescape'))

        if error:
            print(error.as_string())
        else:
            print(result)
