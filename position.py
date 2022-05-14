# POSITION

class Position:
    def __init__(self, idx_, ln_, col_, fn_, ftxt_):
        self.idx = idx_
        self.ln = ln_
        self.col = col_
        self.fn = fn_
        self.ftxt = ftxt_


    def advance(self, current_char=None):
        self.idx += 1
        self.col += 1

        if current_char == '\n':
            self.ln += 1
            self.col = 0
        
        return self
    

    def copy(self):
        return Position(self.idx, self.ln, self.col, self.fn, self.ftxt)
