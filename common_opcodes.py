from opcodes import Opcodes
from decimal import *

class CommonOps:
    def __init__(self):
        pass
    
    def no_create_op(self, values={}):
        return []

    def create_sales_instructions(self, values={
            'tray_no': 5,
            'tray_price': 280,
            'amount': 5*280,
            'section': 'DUKA',
            'by': 'PURITY',
            'date': 1654523316,
            'buyer': 'DUKA',
            'submitted_on': 1654523316
        }):
    
        instr = [
            [Opcodes.PUSH.value, 'sales'],
            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 'world_state'],
            [Opcodes.PUSH.value, 'eggs_collected'],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],

            [Opcodes.PUSH.value, values['section']],
            [Opcodes.CADDR.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.CADDR.value],

            [Opcodes.PUSH.value, values['section']],
            [Opcodes.PUSH.value, values['date']],
            [Opcodes.PUSH.value, values['buyer']],
            [Opcodes.PUSH.value, 3],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, values['tray_no']],
            [Opcodes.PUSH.value, 4],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.MSTORE.value],
            [Opcodes.PUSH.value, values['tray_price']],
            [Opcodes.SWAP.value],
            [Opcodes.PUSH.value, values['tray_no']],
            [Opcodes.SWAP.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'SELL'],
            [Opcodes.CENTRY.value],

            [Opcodes.PUSH.value, values['section']],
            [Opcodes.PUSH.value, 'THIKAFARMERS'],
            [Opcodes.EQ.value],
            [Opcodes.JUMPIF.value],
            
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.BALANCE.value],
            [Opcodes.LT.value],
            [Opcodes.ISZERO.value],
            [Opcodes.PANIC.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.DECRBAL.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.INCRBAL.value],

            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'SHA256'],
            [Opcodes.MLOAD.value],
            [Opcodes.PUSH.value, ''],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.PUSH.value, 5],
            [Opcodes.DUP.value],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 6],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'TRADE'],
            [Opcodes.CENTRY.value],
            [Opcodes.JUMPDEST.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.BALANCE.value],
            [Opcodes.LT.value],
            [Opcodes.ISZERO.value],
            [Opcodes.PANIC.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.DECRBAL.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['section']],
            [Opcodes.INCRBAL.value],

            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'SHA256'],
            [Opcodes.MLOAD.value],
            [Opcodes.PUSH.value, ''],
            [Opcodes.PUSH.value, values['section']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.PUSH.value, 5],
            [Opcodes.DUP.value],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 6],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'TRADE'],
            [Opcodes.CENTRY.value],

            [Opcodes.PUSH.value, 'sales'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.CALCMAINSTATE.value],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 'main'],
            [Opcodes.SWAP.value],
            [Opcodes.UPROOTHASH.value],
            [Opcodes.STOP.value]]
        flattened_code = [item for sublist in instr for item in sublist]
        return flattened_code


    def create_purchases_instructions(self, values={
            'item_no': 5,
            'item_price': 280,
            'amount': 5*280,
            'section': 'FEEDS',
            'by': 'PURITY',
            'date': 1654523316,
            'item_name': 'LAYERS',
            'submitted_on': 1654523316
        }):
    
        instr = [
            [Opcodes.PUSH.value, 'sales'],
            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 'world_state'],
            [Opcodes.PUSH.value, 'eggs_collected'],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],

            [Opcodes.PUSH.value, values['section']],
            [Opcodes.CADDR.value],

            [Opcodes.PUSH.value, values['section']],
            [Opcodes.PUSH.value, values['date']],
            [Opcodes.PUSH.value, values['item_name']],
            [Opcodes.PUSH.value, 3],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, values['item_no']],
            [Opcodes.PUSH.value, 4],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.MSTORE.value],
            [Opcodes.PUSH.value, values['item_price']],
            [Opcodes.SWAP.value],
            [Opcodes.PUSH.value, values['item_no']],
            [Opcodes.SWAP.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'BUY'],
            [Opcodes.CENTRY.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.BALANCE.value],
            [Opcodes.LT.value],
            [Opcodes.ISZERO.value],
            [Opcodes.PANIC.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.DECRBAL.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['section']],
            [Opcodes.INCRBAL.value],

            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, ''],
            [Opcodes.PUSH.value, 'SHA256'],
            [Opcodes.MLOAD.value],
            [Opcodes.PUSH.value, values['section']],
            [Opcodes.PUSH.value, 'BLACK_HOLE'],
            [Opcodes.PUSH.value, 5],
            [Opcodes.DUP.value],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 6],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'TRADE'],
            [Opcodes.CENTRY.value],

            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.CALCMAINSTATE.value],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 'main'],
            [Opcodes.SWAP.value],
            [Opcodes.UPROOTHASH.value],
            [Opcodes.STOP.value]]
        flattened_code = [item for sublist in instr for item in sublist]
        return flattened_code


    def create_eggs_collected_instructions(self, values={
            'a1': 5,
            'a2': 5,
            'b1': 5,
            'b2': 5,
            'c1': 5,
            'c2': 5,
            'house': 5,
            'broken': 5,
            'trays_collected': '3,5',
            'by': 'PURITY',
            'date': 1654523316,
            'submitted_on': 1654523316
        }):
    
        instr = [
            [Opcodes.PUSH.value, 'sales'],
            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 'world_state'],
            [Opcodes.PUSH.value, 'eggs_collected'],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],

            [Opcodes.PUSH.value, values['trays_collected']],
            [Opcodes.PUSH.value, values['date']],
            [Opcodes.PUSH.value, values['house']],
            [Opcodes.PUSH.value, values['broken']],
            [Opcodes.PUSH.value, values['c2']],
            [Opcodes.PUSH.value, values['c1']],
            [Opcodes.PUSH.value, values['b2']],
            [Opcodes.PUSH.value, values['b1']],
            [Opcodes.PUSH.value, values['a2']],
            [Opcodes.PUSH.value, values['a1']],
            [Opcodes.PUSH.value, values['date']],
            [Opcodes.PUSH.value, 1],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'EGGS'],
            [Opcodes.CENTRY.value],
        
            [Opcodes.PUSH.value, 'eggs_collected'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.CALCMAINSTATE.value],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 'main'],
            [Opcodes.SWAP.value],
            [Opcodes.UPROOTHASH.value],
            [Opcodes.STOP.value]]
        flattened_code = [item for sublist in instr for item in sublist]
        return flattened_code


    def create_ds_instructions(self, values={
            'image_url': 'https://firebasestorage.googleapis.com/v0/b/poultry101-6b1ed.appspot.com/o/dead_sick%2FIMG-20210804-WA0000.jpg?alt=media&token=24a1416a-8ec4-4ae9-b12b-21425917ed0d',
            'image_id': 'hello.jpg',
            'reason': 'DISEASE',
            'number': 2,
            'by': 'PURITY',
            'date': 1654523316,
            'section': 'DEAD',
            'location': 'CAGE',
            'submitted_on': 1654523316
        }):
    
        instr = [
            [Opcodes.PUSH.value, 'sales'],
            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 'world_state'],
            [Opcodes.PUSH.value, 'eggs_collected'],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            
            [Opcodes.PUSH.value, values['location']],
            [Opcodes.PUSH.value, values['section']],
            [Opcodes.PUSH.value, values['date']],
            [Opcodes.PUSH.value, values['number']],
            [Opcodes.PUSH.value, 4],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, values['reason']],
            [Opcodes.PUSH.value, 5],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, values['reason']],
            [Opcodes.PUSH.value, values['image_id']],
            [Opcodes.PUSH.value, values['image_url']],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'DS'],
            [Opcodes.CENTRY.value],
            
            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.CALCMAINSTATE.value],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 'main'],
            [Opcodes.SWAP.value],
            [Opcodes.UPROOTHASH.value],
            [Opcodes.STOP.value]]
        flattened_code = [item for sublist in instr for item in sublist]
        return flattened_code


    def create_trade_instructions(self, values={
            'to': 'PURITY',
            'from': 'BLACK_HOLE',
            'amount': 3000,
            'by': 'PURITY',
            'date': 1654523316,
            'submitted_on': 1654523316
        }):
    
        instr = [
            [Opcodes.PUSH.value, 'sales'],
            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 'world_state'],
            [Opcodes.PUSH.value, 'eggs_collected'],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],
            [Opcodes.UPDATECACHE.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['from']],
            [Opcodes.BALANCE.value],
            [Opcodes.LT.value],
            [Opcodes.JUMPIF.value],
            
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['from']],
            [Opcodes.BALANCE.value],
            [Opcodes.EQ.value],
            [Opcodes.ISZERO.value],
            [Opcodes.PANIC.value],
        
            [Opcodes.JUMPDEST.value],
            [Opcodes.PUSH.value, values['to']],
            [Opcodes.CADDR.value],

            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['from']],
            [Opcodes.DECRBAL.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, values['to']],
            [Opcodes.INCRBAL.value],

            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, values['amount']],
            [Opcodes.PUSH.value, ''],
            [Opcodes.PUSH.value, ''],
            [Opcodes.PUSH.value, values['to']],
            [Opcodes.PUSH.value, values['from']],
            [Opcodes.PUSH.value, 5],
            [Opcodes.DUP.value],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 6],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, values['by']],
            [Opcodes.NOW.value],
            [Opcodes.PUSH.value, 'TRADE'],
            [Opcodes.CENTRY.value],

            [Opcodes.PUSH.value, 'trades'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.PUSH.value, 'purchases'],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.PUSH.value, 1],
            [Opcodes.DUP.value],
            [Opcodes.CALCSTATE.value],
            [Opcodes.CALCROOTHASH.value],
            [Opcodes.SHA256.value],
            [Opcodes.UPROOTHASH.value],

            [Opcodes.CALCMAINSTATE.value],
            [Opcodes.SHA256.value],
            [Opcodes.PUSH.value, 'main'],
            [Opcodes.SWAP.value],
            [Opcodes.UPROOTHASH.value],
            [Opcodes.STOP.value]]
        flattened_code = [item for sublist in instr for item in sublist]
        return flattened_code
