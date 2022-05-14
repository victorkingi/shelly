# TOKEN

class Token:
    def __init__(self, type_, value_=None, pos_start_=None, pos_end_=None):
        self.type = type_
        self.value = value_
        
        if pos_start_:
            self.pos_start = pos_start_.copy()
            self.pos_end = pos_start_.copy()
            self.pos_end.advance()
        
        if pos_end_:
            self.pos_end = pos_end_


    def __repr__(self):
        if self.value or self.value == int(0): return f'{self.type}:{self.value}'
        return f'{self.type}'