# UTILITIES

import hashlib
from decimal import *
from log_ import log
from constants import CREATE, DELETE


def update_prev_3_states(prev_3, submitted_on, tx_hash):
    if not prev_3['0']['op']:
        prev_3['0']['op'] = DELETE
        prev_3['0']['tx_hash'] = tx_hash
        prev_3['0']['submitted_on'] = submitted_on

    elif not prev_3['1']['op']:
        prev_3['1']['op'] = DELETE
        prev_3['1']['tx_hash'] = tx_hash
        prev_3['1']['submitted_on'] = submitted_on

    elif not prev_3['2']['op']:
        prev_3['2']['op'] = DELETE
        prev_3['2']['tx_hash'] = tx_hash
        prev_3['2']['submitted_on'] = submitted_on
    
    return prev_3
        


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


def get_tx_data_to_hash(name, cache_state, tx_hash_):
    data = []
    for key in cache_state[name]:
        if key != 'state':
            if 'tx_hash' in cache_state[name][key]:
                if cache_state[name][key]['tx_hash'] == tx_hash_:
                    log.debug(f"tx data found, collection: {name}, id: {key}, tx_hash: {tx_hash_}, {cache_state[name][key]}")
                    if name == 'sales':
                        data.append(cache_state[name][key]['buyer'])
                        data.append(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                        data.append(cache_state[name][key]['section'])
                    elif name == 'purchases':
                        data.append(cache_state[name][key]['item_name'])
                        data.append(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                        data.append(cache_state[name][key]['section'])
                    elif name == 'dead_sick':
                        data.append(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                        data.append(cache_state[name][key]['section'])
                        data.append(cache_state[name][key]['location'])
                    elif name == 'eggs_collected':
                        data.append(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    elif name == 'trades':
                        data.append(cache_state[name][key]['amount'])
                        data.append(cache_state[name][key]['from'])
                        data.append(cache_state[name][key]['to'])
                        data.append(cache_state[name][key]['sale_hash'])
                        data.append(cache_state[name][key]['purchase_hash'])
                        data.append(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
        
    return data


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