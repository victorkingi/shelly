# LEXER
from token_ import Token
from parser import Parser
from error import IllegalCharError, EmptyStringError
from position import Position
from constants import *

class Lexer:
    def __init__(self, fn_, text_=''):
        self.fn = fn_
        self.text = text_
        self.pos = Position(-1, 0, -1, self.fn, self.text)
        self.current_char = None
        self.advance()


    def advance(self):
        self.pos.advance(self.current_char)
        self.current_char = self.text[self.pos.idx] if self.pos.idx < len(self.text) else None
    

    def make_number(self):
        num_str = ''
        dot_count = 0
        pos_start = self.pos.copy()

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
            return Token(TT_INT, int(num_str), pos_start, self.pos)
        else:
            return Token(TT_FLOAT, float(num_str), pos_start, self.pos)


    def make_tokens(self):
        if len(self.text) == 0:
            return [], EmptyStringError()
        
        tokens = []

        while self.current_char != None:
            match self.current_char:
                case val if val in '\t':
                    self.advance()
                case ' ':
                    self.advance()
                case val if val in DIGITS:
                    tokens.append(self.make_number())
                case '+':
                    tokens.append(Token(TT_PLUS, pos_start_=self.pos))
                    self.advance()
                case '-':
                    tokens.append(Token(TT_MINUS, pos_start_=self.pos))
                    self.advance()
                case '*':
                    tokens.append(Token(TT_MUL, pos_start_=self.pos))
                    self.advance()
                case '/':
                    tokens.append(Token(TT_DIV, pos_start_=self.pos))
                    self.advance()
                case '(':
                    tokens.append(Token(TT_LPAREN, pos_start_=self.pos))
                    self.advance()
                case ')':
                    tokens.append(Token(TT_RPAREN, pos_start_=self.pos))
                    self.advance()
                case _:
                    pos_start = self.pos.copy()
                    char = self.current_char
                    self.advance()
                    return [], IllegalCharError(pos_start, self.pos, "'"  + char + "'")

        tokens.append(Token(TT_EOF, pos_start_=self.pos))
        return tokens, None


# This function is what should be called outside this file
def run(fn, text):
    lexer = Lexer(fn, text)
    tokens, error = lexer.make_tokens()
    if error:
        return None, error

    parser_ = Parser(tokens)
    ast = parser_.parse()

    return ast.node, ast.error
