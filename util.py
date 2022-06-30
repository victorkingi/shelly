# UTILITIES

import hashlib
from decimal import *
from log_ import log
from constants import CREATE, DELETE
import collections.abc


eggs_in_tray = Decimal(30)


def get_true_hash_for_tx(tx, collection_name):
    tx_data_to_hash = ''

    if collection_name == 'sales':
        tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['buyer'] + str(tx['tray_price']) + tx['tx_hash'] + str(tx['tray_no']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += prev['section'] + str(prev['submitted_on']['unix']) + prev['buyer'] + str(prev['tray_price']) + prev['tx_hash'] + str(prev['tray_no']) + prev['by'] + str(prev['date']['unix'])

    elif collection_name == 'purchases':
        tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['item_name'] + str(tx['item_price']) + tx['tx_hash'] + str(tx['item_no']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['item_name'] + str(tx['item_price']) + tx['tx_hash'] + str(tx['item_no']) + tx['by'] + str(tx['date']['unix'])
        
    elif collection_name == 'trades':
        tx_data_to_hash += str(tx['amount']) + tx['sale_hash'] + tx['purchase_hash'] + str(tx['submitted_on']['unix']) + tx['from'] + tx['to'] + str(tx['reason']) + tx['tx_hash'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += str(tx['amount']) + tx['sale_hash'] + tx['purchase_hash'] + str(tx['submitted_on']['unix']) + tx['from'] + tx['to'] + str(tx['reason']) + tx['tx_hash'] + tx['by'] + str(tx['date']['unix'])
        
    elif collection_name == 'eggs_collected':
        tx_data_to_hash += str(tx['a1']) + str(tx['a2']) + str(tx['b1']) + str(tx['b2']) + str(tx['c1']) + str(tx['c2']) + str(tx['submitted_on']['unix']) + str(tx['broken']) + str(tx['house']) + tx['tx_hash'] + tx['trays_collected'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += str(tx['a1']) + str(tx['a2']) + str(tx['b1']) + str(tx['b2']) + str(tx['c1']) + str(tx['c2']) + str(tx['submitted_on']['unix']) + str(tx['broken']) + str(tx['house']) + tx['tx_hash'] + tx['trays_collected'] + tx['by'] + str(tx['date']['unix'])
        
    elif collection_name == 'dead_sick':
        tx_data_to_hash += tx['image_id'] + tx['image_url'] + tx['section'] + str(tx['submitted_on']['unix']) + tx['location'] + str(tx['number']) + tx['tx_hash'] + tx['reason'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += tx['image_id'] + tx['image_url'] + tx['section'] + str(tx['submitted_on']['unix']) + tx['location'] + str(tx['number']) + tx['tx_hash'] + tx['reason'] + tx['by'] + str(tx['date']['unix'])

    else:
        log.error("Invalid collection name provided to true hash function")
        return None
    
    log.debug(f"tx data to hash, {tx_data_to_hash}")

    def internal_hash(to_hash):
        m = hashlib.sha256()
        m.update(to_hash.encode())
        return m.hexdigest()
    
    return internal_hash(tx_data_to_hash)


def get_eggs_diff(val1, val2):
    if isinstance(val1, str) and isinstance(val2, str):
        val1 = val1.split(',')
        val2 = val2.split(',')
        val1 = Decimal(val1[0])*eggs_in_tray+Decimal(val1[1])
        val2 = Decimal(val2[0])*eggs_in_tray+Decimal(val2[1])
        res = val1-val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res

    if isinstance(val1, str) and isinstance(val2, Decimal):
        val1 = val1.split(',')
        val1 = Decimal(val1[0])*eggs_in_tray+Decimal(val1[1])
        res = val1-val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res

    if isinstance(val1, Decimal) and isinstance(val2, str):
        val2 = val2.split(',')
        val2 = Decimal(val2[0])*eggs_in_tray+Decimal(val2[1])
        res = val1-val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res

    if isinstance(val1, Decimal) and isinstance(val2, Decimal):
        res = val1-val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res
    
    log.error(f"Failed to subtract eggs, got unknown types, {type(val1)}, {type(val2)}")
    return None, None


def get_eggs(amount):
    if isinstance(amount, Decimal):
        res_str = amount/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', amount

    if isinstance(amount, str):
        res = amount.split(',')
        res = Decimal(res[0])*eggs_in_tray+Decimal(res[1])
        return amount, res
    
    log.error(f"Failed to convert eggs, got unknown type, {type(amount)}")
    return None, None


def increment_eggs(val1, val2):
    if isinstance(val1, str) and isinstance(val2, str):
        val1 = val1.split(',')
        val2 = val2.split(',')
        val1 = Decimal(val1[0])*eggs_in_tray+Decimal(val1[1])
        val2 = Decimal(val2[0])*eggs_in_tray+Decimal(val2[1])
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res

    if isinstance(val1, str) and isinstance(val2, Decimal):
        val1 = val1.split(',')
        val1 = Decimal(val1[0])*eggs_in_tray+Decimal(val1[1])
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res

    if isinstance(val1, Decimal) and isinstance(val2, str):
        val2 = val2.split(',')
        val2 = Decimal(val2[0])*eggs_in_tray+Decimal(val2[1])
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res

    if isinstance(val1, Decimal) and isinstance(val2, Decimal):
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}', res
    
    log.error(f"Failed to increment eggs, got unknown types, {type(val1)}, {type(val2)}")
    return None, None


def reduce_add_eggs(val1, val2):
    if isinstance(val1, str) and isinstance(val2, str):
        val1 = val1.split(',')
        val2 = val2.split(',')
        val1 = Decimal(val1[0])*eggs_in_tray+Decimal(val1[1])
        val2 = Decimal(val2[0])*eggs_in_tray+Decimal(val2[1])
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}'

    if isinstance(val1, str) and isinstance(val2, Decimal):
        val1 = val1.split(',')
        val1 = Decimal(val1[0])*eggs_in_tray+Decimal(val1[1])
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}'

    if isinstance(val1, Decimal) and isinstance(val2, str):
        val2 = val2.split(',')
        val2 = Decimal(val2[0])*eggs_in_tray+Decimal(val2[1])
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}'

    if isinstance(val1, Decimal) and isinstance(val2, Decimal):
        res = val1+val2
        res_str = res/eggs_in_tray
        res_trays = int(res_str)
        eggs_left = (res_str-res_trays)*eggs_in_tray
        eggs_left = Decimal(f'{eggs_left}')
        return f'{res_trays},{round(eggs_left)}'
    
    log.error(f"Failed to increment eggs, got unknown types, {type(val1)}, {type(val2)}")
    return None


def map_nested_dicts_modify(ob, func):
    for k, v in ob.items():
        if isinstance(v, collections.abc.Mapping):
            map_nested_dicts_modify(v, func)
        elif isinstance(v, list):
            for idx, x in enumerate(v):
                ob[k][idx] = func(x)
        else:
            ob[k] = func(v)


def get_collection_hashes(collection_name, cache_state):
    hashes = []
    for key in cache_state[collection_name]:
        if key != 'state' and key != 'prev_states':
            is_valid_hash = re.search("^[a-f0-9]{64}$", key)

            if not is_valid_hash:
                log.warning(f"Key appended not a valid hash, {to_check_hash}")
                return []
            
            hashes.append(key)
    
    return hashes


def string_with_arrows(text, pos_start, pos_end):
    result = ''

    # Calculate indices
    idx_start = max(text.rfind('\n', 0, pos_start.idx), 0)
    idx_end = text.find('\n', idx_start + 1)
    if idx_end < 0:
        idx_end = len(text)
    

    line_count = pos_end.ln - pos_start.ln + 1
    for i in range(line_count):
        # Calculate line columns
        line = text[idx_start:idx_end]
        col_start = pos_start.col if i == 0 else 0
        col_end = pos_end.col if i == line_count - 1 else len(line) - 1

        # Append
        result += line + '\n'
        result += ' ' * col_start + '^' * (col_end - col_start)

        idx_start = idx_end
        idx_end = text.find('\n', idx_start + 1)
        if idx_end < 0:
            idx_end = len(text)
    
    return result.replace('\t', '')