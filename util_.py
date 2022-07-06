# UTILITIES

import hashlib
import random
from decimal import *
from functools import reduce
from log_ import log
from constants import *
import collections.abc

getcontext().traps[FloatOperation] = True
TWOPLACES = Decimal(10) ** -2

def sanity_trays_to_sales_check(cache_state):
    sorted_tuples = sorted(cache_state[EVENTC[SELL]].items(), key=lambda item: item[1]['date']['unix'] if 'date' in item[1] and 'unix' in item[1]['date'] else Decimal(0))
    cache_state[EVENTC[SELL]] = {k: v for k, v in sorted_tuples}
    for k, v in cache_state[EVENTC[SELL]].items():
        if k == 'state' or k == 'prev_states':
            continue
        tray_no = v['tray_no']
        unix_epoch = v['date']['unix']
        all_trays_sold = [Decimal(v['tray_no']) for k, v in cache_state[EVENTC[SELL]].items() if k != 'state' and k != 'prev_states' and v['date']['unix'] <= unix_epoch]
        all_trays_collected = [v['trays_collected'] for k, v in cache_state['eggs_collected'].items() if k != 'state' and k != 'prev_states' and v['date']['unix'] <= unix_epoch]

        all_trays_sold = f'{reduce(lambda x, y: x+y, all_trays_sold, Decimal(0))},0'
        all_trays_collected = reduce(reduce_add_eggs, all_trays_collected, "0,0")
        remain = get_eggs_diff(all_trays_collected, all_trays_sold)[0]
        remain = get_eggs_diff(remain, f'{tray_no},0')[1]

        if Decimal(remain) < Decimal(0):
            return False
    
    return True


# assert all collections have correct entries
def sanity_check(cache_state):
    for k in cache_state:
        if k == 'world_state':
            continue
        
        id_state_set = set(cache_state[k]['state']['all_tx_hashes'].keys())
        id_true_state_set = set([v['true_hash'] for _, v in cache_state[k]['state']['all_tx_hashes'].items()])

        id_col_set = set(cache_state[k].keys())
        id_col_set.remove('state')
        id_col_set.remove('prev_states')

        id_col_true_set = set()
        for v in cache_state[k]:
            if 'true_hash' in cache_state[k][v]:
                id_col_true_set.add(cache_state[k][v]['true_hash'])
        

        id_world_set = set(cache_state['world_state']['main']['all_hashes'][k].keys())
        id_world_true_set = set(cache_state['world_state']['main']['all_hashes'][k].values())

        return (id_state_set == id_col_set == id_world_set) and (id_true_state_set == id_col_true_set == id_world_true_set)


def get_true_hash_for_tx(tx, collection_name):
    tx_data_to_hash = ''

    if collection_name == 'sales':
        tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['buyer'] + str(tx['tray_price']) + str(tx['tray_no']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += prev['section'] + str(prev['submitted_on']['unix']) + prev['buyer'] + str(prev['tray_price']) + str(prev['tray_no']) + prev['by'] + str(prev['date']['unix'])

    elif collection_name == 'purchases':
        tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['item_name'] + str(tx['item_price']) + str(tx['item_no']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += prev['section'] + str(prev['submitted_on']['unix']) + prev['item_name'] + str(prev['item_price']) + str(prev['item_no']) + prev['by'] + str(prev['date']['unix'])
        
    elif collection_name == 'trades':
        tx_data_to_hash += str(tx['amount']) + tx['sale_hash'] + tx['purchase_hash'] + str(tx['submitted_on']['unix']) + tx['from'] + tx['to'] + str(tx['reason']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += str(prev['amount']) + prev['sale_hash'] + prev['purchase_hash'] + str(prev['submitted_on']['unix']) + prev['from'] + prev['to'] + str(prev['reason']) + prev['by'] + str(prev['date']['unix'])
        
    elif collection_name == 'eggs_collected':
        tx_data_to_hash += str(tx['a1']) + str(tx['a2']) + str(tx['b1']) + str(tx['b2']) + str(tx['c1']) + str(tx['c2']) + str(tx['submitted_on']['unix']) + str(tx['broken']) + str(tx['house']) + tx['trays_collected'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += str(prev['a1']) + str(prev['a2']) + str(prev['b1']) + str(prev['b2']) + str(prev['c1']) + str(prev['c2']) + str(prev['submitted_on']['unix']) + str(prev['broken']) + str(prev['house']) + prev['trays_collected'] + prev['by'] + str(prev['date']['unix'])
        
    elif collection_name == 'dead_sick':
        tx_data_to_hash += tx['image_id'] + tx['image_url'] + tx['section'] + str(tx['submitted_on']['unix']) + tx['location'] + str(tx['number']) + tx['reason'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in tx['prev_values']:
                prev = tx['prev_values'][k]
                tx_data_to_hash += prev['image_id'] + prev['image_url'] + prev['section'] + str(prev['submitted_on']['unix']) + prev['location'] + str(prev['number']) + prev['reason'] + prev['by'] + str(prev['date']['unix'])

    else:
        log.error("Invalid collection name provided to true hash function")
        return None
    
    message = f"tx data to hash, {tx_data_to_hash}"
    message = message[:MAX_CHAR_COUNT_LOG]+"..."  if len(message) > MAX_CHAR_COUNT_LOG else message
    #log.debug(message)

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


def rgba_random_generator(alpha=1):
    return f'rgba({random.randint(0, 255)}, {random.randint(0, 255)}, {random.randint(0, 255)}, {alpha})'


def to_area_chart_dict(x_axis=[], y_axis=[], label=''):
    if len(x_axis) != len(y_axis):
        return None
    data = {
        'backgroundColor': [],
        'borderColor': [],
        'label': label,
        'y': y_axis,
        'x': x_axis
    }

    for _, _ in enumerate(x_axis):
        data['backgroundColor'].append(rgba_random_generator(alpha=0.2))
        data['borderColor'].append(rgba_random_generator(alpha=1))

    return data

# given a date, get laying percent on that day
def laying_percent_for_a_day(unix_epoch, dead_docs, eggs):
    vals = [ Decimal(value['number']) for key, value in dead_docs.items() if key != 'state' and key != 'prev_states' and dead_docs[key]['section'] == 'DEAD' and Decimal(str(dead_docs[key]['date']['unix'])) <= unix_epoch ]
    all_dead = reduce(lambda a, b: a + b, vals, 0)
    rem_birds = starting_birds_no - all_dead
    
    total_eggs = get_eggs(eggs)[1]
    percent = (total_eggs / Decimal(rem_birds)) * Decimal(100)
    try:
        percent = percent.quantize(TWOPLACES)
    except InvalidOperation:
        log.error(f"Invalid Decimal Operation on daily laying percent, value: {percent}")
        return None

    return percent


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