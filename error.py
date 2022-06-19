# ERRORS
from util import string_with_arrows

class Error:
    def __init__(self, error_name_, pos_start_=None, pos_end_=None, details_=None):
        self.pos_start = pos_start_
        self.pos_end = pos_end_
        self.error_name = error_name_
        self.details = details_
    

    def as_string(self):
        if self.pos_start is None and self.pos_end is None and self.details is None:
            result = f'{self.error_name}\n'
            return result
        else:
            result = f'{self.error_name}: {self.details}\n'
            result += f'File {self.pos_start.fn}, line {self.pos_start.ln + 1}'
            result += '\n\n' + string_with_arrows(self.pos_start.ftxt, self.pos_start, self.pos_end)
            return result


class IllegalCharError(Error):
    def __init__(self, pos_start, pos_end, details):
        super().__init__('Illegal Character', pos_start, pos_end, details)


class EmptyStringError(Error):
    def __init__(self, pos_start, pos_end, details='null'):
        super().__init__('Empty String', pos_start, pos_end, details)


class InvalidSyntaxError(Error):
    def __init__(self, pos_start, pos_end, details=''):
        super().__init__('Invalid Syntax', pos_start, pos_end, details)


class RuntimeError(Error):
    def __init__(self, pos_start, pos_end, details=''):
        super().__init__('Runtime Error', pos_start, pos_end, details)

class NoVisitMethodError(Error):
    def __init__(self, node):
        super().__init__(f'No visit_{type(node).__name__} method defined')

