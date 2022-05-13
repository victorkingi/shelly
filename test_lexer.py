import unittest2
from lexer import Lexer

class TestLexer(unittest.TestCase):

    def test_illegal_char(self):
        text = "dsagf"
        lexer = Lexer(text)
        tokens, error = lexer.make_tokens()
        self.assertEqual(tokens, [])
        self.assertEqual(error.as_string(), f'Illegal Character: {text[0]}')

