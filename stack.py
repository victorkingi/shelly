class Stack:
    def __init__(self): self.stack = []
    
    def push(self,element):
        if type(element) != list:
            self.stack.append(element)
        else:
            for t in element:
                if type(element) != list:
                    self.stack.append(t)
                else:
                    self.push(t)
    
    
    def pop(self):
        elem = self.stack[-1] 
        self.stack.pop(-1)
        return elem

    def peek(self): return self.stack[-1]
    def peek2(self): return self.stack[-2]
    def peek_n(self, n): return self.stack[(-1*n):]
    def bottom(self): return self.stack[0]
    def is_stack_empty(self):
        if len(self.stack)>=1:
            return False
        else:
            return True
    def get_stack(self): return self.stack
    def size(self): return len(self.stack)
    def clear_stack(self): self.stack = []