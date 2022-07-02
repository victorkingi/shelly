from decimal import *

getcontext().traps[FloatOperation] = True
TWOPLACES = Decimal(10) ** -2

MAX_CHAR_COUNT_LOG = 90
other = 'other'
eggs_in_tray = Decimal(30)
starting_birds_no = Decimal(500)

# DIGITS

DIGITS = '0123456789'

# TOKENS

TT_INT = 'INT'
TT_FLOAT = 'FLOAT'
TT_PLUS = 'PLUS'
TT_MINUS = 'MINUS'
TT_MUL = 'MUL'
TT_DIV = 'DIV'
TT_LPAREN = 'LPAREN'
TT_RPAREN = 'RPAREN'
TT_EOF = 'EOF'

# System
CREATE = 'CREATE'
DELETE = 'DELETE'

SELL = 'SELL'
TRADE = 'TRADE'
BUY = 'BUY'
DS = 'DS'
EGGS = 'EGGS'

EVENTC = {SELL: 'sales', TRADE: 'trades', BUY: 'purchases', DS: 'dead_sick', EGGS: 'eggs_collected'}

# sections
VALID_SELL_SECTIONS = set(('CAKES', 'DUKA', 'THIKAFARMERS', 'SOTHER'))
VALID_BUY_SECTIONS = set(('PURITY', 'FEEDS', 'DRUGS', 'POTHER'))

# valid buyers
buyers = set((
    'Eton',
    "Sang'",
    'Karithi',
    'Titus',
    'Mwangi',
    'Lynn',
    'Gituku',
    "Lang'at",
    'Wahome',
    'Kamau',
    'Wakamau',
    'Simiyu',
    'Kinyanjui',
    'Benson',
    'Ben',
    'Rose',
    'Gitonyi',
    'Muthomi',
    'forgotjeff'
))
b_upper = map(lambda x: x.upper(), buyers)
VALID_BUYERS = set(b_upper)
