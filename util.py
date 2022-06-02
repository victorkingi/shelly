# UTILITIES

import hashlib

def get_collection_hashes(collection_name, cache_state):
    hashes = []
    for key in cache_state[collection_name]:
        if key != 'state':
            hashes.append(cache_state[collection_name][key]['tx_hash'])
    
    print("all hashes:", hashes)
    return hashes


def get_tx_data_to_hash(name, cache_state, tx_hash_):
    data = []
    for key in cache_state[name]:
        if key != 'state':
            if cache_state[name][key]['tx_hash'] == tx_hash_:
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
    
    print("all hashes:", hashes)
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