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
    def bottom(self): return self.stack[0]
    def isEmpty(self): return len(self.stack)==0:
    def get_stack(self): return self.stack
    def size(self): return len(self.stack)