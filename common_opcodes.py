from opcodes import Opcodes

def create_sale_instructions(values={
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
        [Opcodes.PUSH.value, 3],
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

        [Opcodes.PUSH.value, values['amount']],
        [Opcodes.PUSH.value, 'BLACK_HOLE'],
        [Opcodes.BALANCE.value],
        [Opcodes.LT.value],
        [Opcodes.ISZERO.value],
        [Opcodes.PANIC.value],
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

        [Opcodes.PUSH.value, values['amount']],
        [Opcodes.PUSH.value, 'BLACK_HOLE'],
        [Opcodes.BALANCE.value],
        [Opcodes.LT.value],
        [Opcodes.ISZERO.value],
        [Opcodes.PANIC.value],
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


def create_buy_instructions(values={
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
        [PUSH, 'sales'],
        [PUSH, 'purchases'],
        [PUSH, 'trades'],
        [PUSH, 'world_state'],
        [PUSH, 'eggs_collected'],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],

        [PUSH, values['section']],
        [CADDR],

        [PUSH, values['section']],
        [PUSH, values['date']],
        [PUSH, values['item_name']],
        [PUSH, 3],
        [DUP],
        [PUSH, 3],
        [SHA256],
        [PUSH, 1],
        [DUP],
        [MSTORE],
        [PUSH, values['item_price']],
        [SWAP],
        [PUSH, values['item_no']],
        [SWAP],
        [PUSH, values['by']],
        [NOW],
        [PUSH, 'BUY'],
        [CENTRY],

        [PUSH, values['amount']],
        [PUSH, 'BLACK_HOLE'],
        [BALANCE],
        [LT],
        [ISZERO],
        [PANIC],
        [NOW],
        [PUSH, values['amount']],
        [PUSH, ''],
        [PUSH, 'SHA256'],
        [MLOAD],
        [PUSH, values['section']],
        [PUSH, 'BLACK_HOLE'],
        [PUSH, 5],
        [DUP],
        [NOW],
        [PUSH, 6],
        [SHA256],
        [PUSH, values['by']],
        [NOW],
        [PUSH, 'TRADE'],
        [CENTRY],

        [PUSH, 'trades'],
        [PUSH, 1],
        [DUP],
        [PUSH, 1],
        [DUP],
        [CALCSTATE],
        [CALCROOTHASH],
        [SHA256],
        [UPROOTHASH],

        [PUSH, 'purchases'],
        [PUSH, 1],
        [DUP],
        [PUSH, 1],
        [DUP],
        [CALCSTATE],
        [CALCROOTHASH],
        [SHA256],
        [UPROOTHASH],

        [CALCMAINSTATE],
        [SHA256],
        [PUSH, 'main'],
        [SWAP],
        [UPROOTHASH],
        [STOP]]
    flattened_code = [item for sublist in instr for item in sublist]
    return flattened_code


def create_egg_instructions(values={
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
        [PUSH, 'sales'],
        [PUSH, 'purchases'],
        [PUSH, 'trades'],
        [PUSH, 'world_state'],
        [PUSH, 'eggs_collected'],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [PUSH, values['trays_collected']],
        [PUSH, values['date']],
        [PUSH, values['house']],
        [PUSH, values['broken']],
        [PUSH, values['c2']],
        [PUSH, values['c1']],
        [PUSH, values['b2']],
        [PUSH, values['b1']],
        [PUSH, values['a2']],
        [PUSH, values['a1']],
        [PUSH, values['date']],
        [PUSH, 1],
        [SHA256],
        [PUSH, values['by']],
        [NOW],
        [PUSH, 'EGGS'],
        [CENTRY],
    
        [PUSH, 'eggs_collected'],
        [PUSH, 1],
        [DUP],
        [PUSH, 1],
        [DUP],
        [CALCSTATE],
        [CALCROOTHASH],
        [SHA256],
        [UPROOTHASH],

        [CALCMAINSTATE],
        [SHA256],
        [PUSH, 'main'],
        [SWAP],
        [UPROOTHASH],
        [STOP]]
    flattened_code = [item for sublist in instr for item in sublist]
    return flattened_code


def create_ds_instructions(values={
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
        [PUSH, 'sales'],
        [PUSH, 'purchases'],
        [PUSH, 'trades'],
        [PUSH, 'world_state'],
        [PUSH, 'eggs_collected'],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],

        [PUSH, values['section']],
        [CADDR],
        
        [PUSH, values['section']],
        [PUSH, values['date']],
        [PUSH, values['item_name']],
        [PUSH, 3],
        [DUP],
        [PUSH, 3],
        [SHA256],
        [PUSH, 1],
        [DUP],
        [MSTORE],
        [PUSH, values['item_price']],
        [SWAP],
        [PUSH, values['item_no']],
        [SWAP],
        [PUSH, values['by']],
        [NOW],
        [PUSH, 'BUY'],
        [CENTRY],

        [PUSH, values['amount']],
        [PUSH, 'BLACK_HOLE'],
        [BALANCE],
        [LT],
        [ISZERO],
        [PANIC],
        [NOW],
        [PUSH, values['amount']],
        [PUSH, ''],
        [PUSH, 'SHA256'],
        [MLOAD],
        [PUSH, values['section']],
        [PUSH, 'BLACK_HOLE'],
        [PUSH, 5],
        [DUP],
        [NOW],
        [PUSH, 6],
        [SHA256],
        [PUSH, values['by']],
        [NOW],
        [PUSH, 'TRADE'],
        [CENTRY],

        [PUSH, 'trades'],
        [PUSH, 1],
        [DUP],
        [PUSH, 1],
        [DUP],
        [CALCSTATE],
        [CALCROOTHASH],
        [SHA256],
        [UPROOTHASH],

        [PUSH, 'purchases'],
        [PUSH, 1],
        [DUP],
        [PUSH, 1],
        [DUP],
        [CALCSTATE],
        [CALCROOTHASH],
        [SHA256],
        [UPROOTHASH],

        [CALCMAINSTATE],
        [SHA256],
        [PUSH, 'main'],
        [SWAP],
        [UPROOTHASH],
        [STOP]]
    flattened_code = [item for sublist in instr for item in sublist]
    return flattened_code


def create_trade_instructions(values={
        'to': 'PURITY',
        'from': 'BLACK_HOLE',
        'amount': 3000,
        'by': 'PURITY',
        'date': 1654523316,
        'submitted_on': 1654523316
    }):
  
    instr = [
        [PUSH, 'sales'],
        [PUSH, 'purchases'],
        [PUSH, 'trades'],
        [PUSH, 'world_state'],
        [PUSH, 'eggs_collected'],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [UPDATECACHE],
        [PUSH, values['amount']],
        [PUSH, values['from']],
        [BALANCE],
        [LT],
        [ISZERO],
        [PANIC],

        [PUSH, values['to']],
        [CADDR],

        [NOW],
        [PUSH, values['amount']],
        [PUSH, ''],
        [PUSH, ''],
        [PUSH, values['to']],
        [PUSH, values['from']],
        [PUSH, 5],
        [DUP],
        [NOW],
        [PUSH, 6],
        [SHA256],
        [PUSH, values['by']],
        [NOW],
        [PUSH, 'TRADE'],
        [CENTRY],

        [PUSH, 'trades'],
        [PUSH, 1],
        [DUP],
        [PUSH, 1],
        [DUP],
        [CALCSTATE],
        [CALCROOTHASH],
        [SHA256],
        [UPROOTHASH],

        [CALCMAINSTATE],
        [SHA256],
        [PUSH, 'main'],
        [SWAP],
        [UPROOTHASH],
        [STOP]]
    flattened_code = [item for sublist in instr for item in sublist]
    return flattened_code
