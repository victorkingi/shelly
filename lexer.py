# LEXER
from token_ import Token
from error import IllegalCharError, EmptyStringError

# DIGITS

DIGITS = '0123456789'

# TOKENS

TT_INT = 'INT'
TT_FLOAT = 'FLOAT'
TT_PLUS = 'PLUS'
TT_MINUS = 'MINUS'
TT_MUL = 'MUL'
TT_DIV = 'DIV'
TT_LPAREN = 'LPAREN'
TT_RPAREN = 'RPAREN'

class Lexer:
    def __init__(self, text_=''):
        self.text = text_
        self.pos = -1
        self.current_char = None
        self.sanitize()
        self.advance()

    
    def sanitize(self):
        self.text = self.text.replace(" ", "")
        self.text = self.text.replace("\t", "")
    

    def advance(self):
        self.pos += 1
        self.current_char = self.text[self.pos] if self.pos < len(self.text) else None
    

    def make_number(self):
        num_str = ''
        dot_count = 0

        while self.current_char != None and self.current_char in DIGITS + '.':
            if self.current_char == '.':
                if dot_count == 1: 
                    break
                dot_count += 1
                num_str += '.'
            else:
                num_str += self.current_char
            
            self.advance()
            
        
        if dot_count == 0:
            return Token(TT_INT, int(num_str))
        else:
            return Token(TT_FLOAT, float(num_str))


    def make_tokens(self):
        if len(self.text) == 0:
            return [], EmptyStringError()
        
        tokens = []

        while self.current_char != None:
            match self.current_char:
                case val if val in DIGITS:
                    tokens.append(self.make_number())
                case '+':
                    tokens.append(Token(TT_PLUS))
                    self.advance()
                case '-':
                    tokens.append(Token(TT_MINUS))
                    self.advance()
                case '*':
                    tokens.append(Token(TT_MUL))
                    self.advance()
                case '/':
                    tokens.append(Token(TT_DIV))
                    self.advance()
                case '(':
                    tokens.append(Token(TT_LPAREN))
                    self.advance()
                case ')':
                    tokens.append(Token(TT_RPAREN))
                    self.advance()
                case _:
                    char = self.current_char
                    self.advance()
                    return [], IllegalCharError("'"  + char + "'")
    
        return tokens, None


# This function is what should be called outside this file
def run_lexer(text):
    lexer = Lexer(text)
    tokens, error = lexer.make_tokens()

    return tokens, error
