# Instructions
from opcodes import *

def push(stack, elem):
    stack.push(elem)
    return stack

def add(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b + a)
    return stack


def sub(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b - a)
    return stack


def mul(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b * a)
    return stack

def div(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b / a)
    return stack


inst_mapping = {
    str(PUSHNUM): push,
    str(ADD): add,
    str(MUL): mul,
    str(SUB): sub,
    str(DIV): div 
}