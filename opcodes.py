# OPCODES
from enum import Enum, auto

class AutoName(Enum):
    def _generate_next_value_(name, start, count, last_values):
        return count


class Opcodes(AutoName):
    # Main
    PUSH = auto()
    DUP = auto()
    SWAP = auto()
    NOW = auto()
    JUMPIF = auto()
    JUMPDEST = auto()

    # arithmetic
    ADD = auto()
    MUL = auto()
    SUB = auto()
    DIV = auto()

    #Comparison
    LT = auto()
    GT = auto()
    EQ = auto()
    ISZERO = auto()

    # Hash
    SHA256 = auto()
    ROOTHASH = auto()

    # data manipulation
    CENTRY = auto()
    DENTRY = auto()
    CADDR = auto()
    DADDR = auto()
    UPDATECACHE = auto()
    STATE = auto()
    LAYINGPERCENT = auto()
    PREPFINALISE = auto()
    CALCSTATE = auto()
    CALCROOTHASH = auto()
    UPROOTHASH = auto()
    CALCMAINSTATE = auto()
    BALANCE = auto()

    # memory
    MLOAD = auto()
    MSTORE = auto()

    # terminate
    STOP = auto()
    PANIC = auto()

    POP = auto()
    DECRBAL = auto()
    INCRBAL = auto()
    TRAYSAVAIL = auto()
    UIENTRIES = auto()
    VERIFYCOL = auto()
    DASHBOARD = auto()
    WRITE = auto()
