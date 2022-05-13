# ERRORS

class Error:
    def __init__(self, error_name_, details_):
        self.error_name = error_name_
        self.details = details_
    

    def as_string(self):
        result = f'{self.error_name}: {self.details}'
        return result


class IllegalCharError(Error):
    def __init__(self, details__):
        super().__init__('Illegal Character', details__)


class EmptyStringError(Error):
    def __init__(self, details__=''):
        super().__init__('Empty String', details__)
