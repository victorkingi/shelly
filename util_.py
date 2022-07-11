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


def dup_exists(l):
    seen = set()
    dupes = []

    for x in l:
        if x in seen:
            dupes.append(x)
        else:
            seen.add(x)
    return dupes


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



def sanity_check_trays_to_sales(cache_state):
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
def sanity_check_hashes_match(cache_state, db):
    is_safe = []
    for k in cache_state:
        if k == 'world_state':
            continue
        
        # check for duplicates
        dups = dup_exists(list(cache_state[k]['state']['all_tx_hashes'].keys()))
        dups_true = dup_exists(list([v['true_hash'] for _, v in cache_state[k]['state']['all_tx_hashes'].items()]))
        if dups or dups_true:
            print(k)
            for l in set(dups_true):
                id = [b for b, n in cache_state[k]['state']['all_tx_hashes'].items() if n['true_hash'] == l]
                doc = db.collection(k).document(id[0]).get()
                doc2 = db.collection(k).document(id[1]).get()
                def internal_hash(to_hash):
                    m = hashlib.sha256()
                    m.update(to_hash.encode())
                    return m.hexdigest()
                def get_hash():
                    if k == 'trades':
                        return internal_hash(str(int(doc2.to_dict()['date']['unix']))+doc.to_dict()['from']+doc.to_dict()['to']+doc.to_dict()['purchase_hash']+doc.to_dict()['sale_hash']+str(int(doc.to_dict()['amount']))), internal_hash(str(float(doc2.to_dict()['date']['unix']))+doc.to_dict()['from']+doc.to_dict()['to']+doc.to_dict()['purchase_hash']+doc.to_dict()['sale_hash']+str(float(doc.to_dict()['amount'])))
                print(id)
                if get_hash()[0] in id:
                    print("removing", get_hash()[0])
                elif get_hash()[1] in id:
                    print("removing", get_hash()[1])

                '''
                db.collection(k).document(internal_hash(str(doc.to_dict()['date']['unix']))).delete()
                del cache_state[k]['state']['all_tx_hashes'][internal_hash(str(doc.to_dict()['date']['unix']))]
                del cache_state['world_state']['main']['all_hashes'][k][internal_hash(str(doc.to_dict()['date']['unix']))]
                db.collection(k).document('state').update({
                    'all_tx_hashes': cache_state[k]['state']['all_tx_hashes']
                })
                db.collection('world_state').document('main').update({
                    f'all_hashes.{k}': cache_state['world_state']['main']['all_hashes'][k]
                })
                '''

            log.error(f"Duplicate entries in state {k}: entry hash: {dups}, true hash: {dups_true}")
            return False
        
        dups = dup_exists(list(cache_state['world_state']['main']['all_hashes'][k].keys()))
        dups_true = dup_exists(list(cache_state['world_state']['main']['all_hashes'][k].values()))
        if dups or dups_true:
            log.error(f"Duplicate entries in world state: entry hash: {dups}, true hash: {dups_true}")
            return False
        
        id_state_set = set(cache_state[k]['state']['all_tx_hashes'].keys())
        id_true_state_set = set([v['true_hash'] for _, v in cache_state[k]['state']['all_tx_hashes'].items()])

        id_col_set = set(cache_state[k].keys())
        id_col_set.remove('state')
        id_col_set.remove('prev_states')

        id_col_true_set = set()
        id_col_true_list = []
        for v in cache_state[k]:
            if v == 'prev_states' or v == 'state':
                continue
            id_col_true_set.add(cache_state[k][v]['true_hash'])
            id_col_true_list.append(cache_state[k][v]['true_hash'])
        
        dups = dup_exists(list(cache_state[k].keys()))
        dups_true = dup_exists(id_col_true_list)
        if dups or dups_true:
            log.error(f"Duplicate entries in collection: entry hash: {dups}, true hash: {dups_true}")
            return False

        id_world_set = set(cache_state['world_state']['main']['all_hashes'][k].keys())
        id_world_true_set = set(cache_state['world_state']['main']['all_hashes'][k].values())

        is_safe.append((id_state_set == id_col_set == id_world_set) and (id_true_state_set == id_col_true_set == id_world_true_set))
        
    return reduce(lambda x, y: x and y, is_safe, True)


# assert tx_ui contains only all entries and nothing else
def sanity_check_all_txs_included(cache_state, cache_ui_txs, db):
    all_hashes = []
    for k in cache_state:
        if k == 'world_state':
            continue

        id_world_set = [x for x in cache_state['world_state']['main']['all_hashes'][k]]
        id_world_true_set = [y for _, y in cache_state['world_state']['main']['all_hashes'][k].items()]
        all_hashes = [*id_world_set, *id_world_true_set, *all_hashes]
    
    tx_ui_hashes = [x for x in cache_ui_txs]
    tx_ui_hashes = tx_ui_hashes + [v['data']['true_hash'] for _,v in cache_ui_txs.items()]
    dups = dup_exists(tx_ui_hashes)
    if dups:
        log.error(f"Duplicate entries in tx_ui: entry/true hash: {dups}")
        return False

    return set(tx_ui_hashes) == set(all_hashes)


# assert every sale and purchase matches to a trade and vice versa such that no loose entries exist
def sanity_check_ps_to_trade(cache_state):
    sale_hashes = set(cache_state[EVENTC[SELL]].keys())
    purchase_hashes = set(cache_state[EVENTC[BUY]].keys())
    sp_set = sale_hashes.union(purchase_hashes)
    trade_sale_hashes = set([v['purchase_hash'] or v['sale_hash'] for k, v in cache_state[EVENTC[TRADE]].items() if k != 'prev_states' and k != 'state'])
    trade_sale_hashes.remove('')
    sp_set.remove('state')
    sp_set.remove('prev_states')

    outlier_trade = trade_sale_hashes - sp_set
    outlier_sp = sp_set - trade_sale_hashes
    return outlier_sp == outlier_trade == set()


def get_true_hash_for_tx(tx, collection_name):
    tx_data_to_hash = ''
    tx = dict(tx)
    map_nested_dicts_modify(tx, lambda x: int(x) if isinstance(x, Decimal) or isinstance(x, float) else x)

    if collection_name == 'sales':
        tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['buyer'] + str(tx['tray_price']) + str(tx['tray_no']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in range(len(tx['prev_values'].keys())):
                prev = tx['prev_values'][str(k)]
                tx_data_to_hash += prev['section'] + str(prev['submitted_on']['unix']) + prev['buyer'] + str(prev['tray_price']) + str(prev['tray_no']) + prev['by'] + str(prev['date']['unix'])

    elif collection_name == 'purchases':
        tx_data_to_hash += tx['section'] + str(tx['submitted_on']['unix']) + tx['item_name'] + str(tx['item_price']) + str(tx['item_no']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in range(len(tx['prev_values'].keys())):
                prev = tx['prev_values'][str(k)]
                tx_data_to_hash += prev['section'] + str(prev['submitted_on']['unix']) + prev['item_name'] + str(prev['item_price']) + str(prev['item_no']) + prev['by'] + str(prev['date']['unix'])
        
    elif collection_name == 'trades':
        tx_data_to_hash += str(tx['amount']) + tx['sale_hash'] + tx['purchase_hash'] + str(tx['submitted_on']['unix']) + tx['from'] + tx['to'] + str(tx['reason']) + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in range(len(tx['prev_values'].keys())):
                prev = tx['prev_values'][str(k)]
                tx_data_to_hash += str(prev['amount']) + prev['sale_hash'] + prev['purchase_hash'] + str(prev['submitted_on']['unix']) + prev['from'] + prev['to'] + str(prev['reason']) + prev['by'] + str(prev['date']['unix'])
        
    elif collection_name == 'eggs_collected':
        tx_data_to_hash += str(tx['a1']) + str(tx['a2']) + str(tx['b1']) + str(tx['b2']) + str(tx['c1']) + str(tx['c2']) + str(tx['submitted_on']['unix']) + str(tx['broken']) + str(tx['house']) + tx['trays_collected'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in range(len(tx['prev_values'].keys())):
                prev = tx['prev_values'][str(k)]
                tx_data_to_hash += str(prev['a1']) + str(prev['a2']) + str(prev['b1']) + str(prev['b2']) + str(prev['c1']) + str(prev['c2']) + str(prev['submitted_on']['unix']) + str(prev['broken']) + str(prev['house']) + prev['trays_collected'] + prev['by'] + str(prev['date']['unix'])
        
    elif collection_name == 'dead_sick':
        tx_data_to_hash += tx['image_id'] + tx['image_url'] + tx['section'] + str(tx['submitted_on']['unix']) + tx['location'] + str(tx['number']) + tx['reason'] + tx['by'] + str(tx['date']['unix'])
        
        if tx['prev_values']:
            log.debug(f"found prev values dict of size {len(tx['prev_values'].keys())}")
            for k in range(len(tx['prev_values'].keys())):
                prev = tx['prev_values'][str(k)]
                tx_data_to_hash += prev['image_id'] + prev['image_url'] + prev['section'] + str(prev['submitted_on']['unix']) + prev['location'] + str(prev['number']) + prev['reason'] + prev['by'] + str(prev['date']['unix'])

    else:
        log.error("Invalid collection name provided to true hash function")
        return None
    
    message = f"tx data to hash, {tx_data_to_hash}"
    message = message[:MAX_CHAR_COUNT_LOG]+"..."  if len(message) > MAX_CHAR_COUNT_LOG else message
    log.debug(message)

    def internal_hash(to_hash):
        m = hashlib.sha256()
        m.update(to_hash.encode())
        return m.hexdigest()
    
    return internal_hash(tx_data_to_hash)


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