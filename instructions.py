# Instructions
from functools import reduce
from decimal import *
from firebase_admin import credentials
from firebase_admin import firestore
from datetime import datetime as dt
from dateutil import tz
import time
import sys

from opcodes import *
from util import *
from log_ import log
from constants import *

import time
import hashlib
import firebase_admin

getcontext().traps[FloatOperation] = True
TWOPLACES = Decimal(10) ** -2 

cred = credentials.Certificate("core101-3afde-firebase-adminsdk-sxm20-194a475b51.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

NBO = tz.gettz('Africa/Nairobi')

cache_state = { 
    'sales': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {},
            'prev_3_states': {'0': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '1': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '2': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }}
        },
        'prev_states': {}
    },
    'purchases': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {},
            'prev_3_states': {'0': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '1': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '2': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }}
        },
        'prev_states': {}
    },
    'eggs_collected': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {},
            'prev_3_states': {'0': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '1': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '2': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }}
        },
        'prev_states': {}
    },
    'dead_sick': {
       'state': {
            'root_hash': '',
            'all_tx_hashes': {},
            'prev_3_states': {'0': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '1': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '2': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }}
        },
        'prev_states': {}
    },
    'trades': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {},
            'prev_3_states': {'0': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '1': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }, '2': {
                'op': '',
                'tx_hash': '',
                'submitted_on': {'unix': 0, 'locale': ''}
            }}
        },
        'prev_states': {}
    }
}
cache_accounts = {'BLACK_HOLE': sys.maxsize }
cache_deleted = {} # no need to keep track of this as entries are only dumped into it


def push(elem=None, stack=None, memory=None, pc=None, analysed=None):
    prev_type = type(elem)
    log.debug(f"{pc}: PUSH {elem}, {type(elem)}")
    pc += 2

    if isinstance(elem, float) or isinstance(elem, int):
        elem = Decimal(elem)
        log.debug(f"converted from {prev_type} to {type(elem)}")

    if isinstance(elem, Decimal) or isinstance(elem, str):
        stack.push(elem)
        return stack, memory, pc, cache_state, cache_accounts
    else:
        log.error(f"Attempted to push not a str or a decimal type, {type(elem)}")
        return None, None, None, None, None


def add(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: ADD")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(b + a)
    
    return stack, memory, pc, cache_state, cache_accounts


def sub(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: SUB")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(b - a)
    return stack, memory, pc, cache_state, cache_accounts


def mul(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: MUL")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(b * a)
    return stack, memory, pc, cache_state, cache_accounts


def div(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DIV")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    if not a:
        # division by zero
        log.error("Division by zero")
        return None, None, None, None, None
    stack.push(b / a)
    
    return stack, memory, pc, cache_state, cache_accounts


def dup(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DUP")
    pc += 1

    num = stack.pop()
    arr = []

    for i in range(int(num)):
        arr.append(stack.pop())

    arr.reverse() # preserve LIFO
    stack.push(arr)
    stack.push(arr)

    return stack, memory, pc, cache_state, cache_accounts


def stop(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: STOP")
    pc += 1

    if stack.size() == 1:
        empty_state = { 
            'sales': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {}, '1': {}, '2': {}}
                },
                'prev_states': {}
            },
            'purchases': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {}, '1': {}, '2': {}}
                },
                'prev_states': {}
            },
            'eggs_collected': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {}, '1': {}, '2': {}}
                },
                'prev_states': {}
            },
            'dead_sick': {
            'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {}, '1': {}, '2': {}}
                },
                'prev_states': {}
            },
            'trades': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {},
                    'prev_3_states': {'0': {}, '1': {}, '2': {}}
                },
                'prev_states': {}
            }
        }
        empty_accounts = {}
        if empty_accounts == cache_accounts and empty_state == cache_state:
            # successful exit
            val = stack.pop()
            if not isinstance(val, Decimal):
                log.warning(f"Non Dec value popped from stack, got {type(val)} expected decimal, value: {val}")
                stack.push(val)
                return stack, memory, -1, cache_state, cache_accounts
            
            try:
                val = val.quantize(TWOPLACES)
            except InvalidOperation:
                log.error(f"Invalid Decimal Operation; stack value: {val}")
                return None, None, None, None, None
            
            if val.is_nan():
                log.error(f"NaN value popped from stack, {val}")
                return None, None, None, None, None
            
            stack.push(val)
            return stack, memory, -1, cache_state, cache_accounts


    if stack.size():
        log.error(f"Stack still contains: {stack.get_stack()}")
        return None, None, None, None, None

    # successful exit
    return stack, memory, -1, cache_state, cache_accounts


# pushes root hash of a collection to stack
def root_hash(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: ROOTHASH")
    pc += 1

    collection_name = stack.pop()

    if collection_name in cache_state:
        if 'state' in cache_state[collection_name]:
            if 'root_hash' in cache_state[collection_name]['state']:
                stack.push(cache_state[collection_name]['state']['root_hash'])
                return stack, memory, pc, cache_state, cache_accounts
    
    log.error(f"collection name {collection_name} does not exist or state and root hash do not exist")
    return None, None, None, None, None


def sha256(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: SHA256")
    pc += 1

    m = hashlib.sha256()
    num_of_elements = stack.pop()
    to_hash = ''

    for i in range(int(num_of_elements)):
        val = stack.pop()
        to_hash += str(val)
    
    log.debug(f"all hashes: {to_hash}")
    m.update(to_hash.encode())
    stack.push(m.hexdigest())

    return stack, memory, pc, cache_state, cache_accounts


def is_zero(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: ISZERO")
    pc += 1

    val = stack.pop()

    stack.push(Decimal(1) if val == Decimal(0) else Decimal(0))

    return stack, memory, pc, cache_state, cache_accounts


def eq(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: EQ")
    pc += 1

    a = stack.pop()
    b = stack.pop()

    stack.push(Decimal(1) if a == b else Decimal(0))
    return stack, memory, pc, cache_state, cache_accounts


# followed by sha256
def collection_hashes_to_hash(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: COLLHASH")
    pc += 1

    collection_name = stack.pop()
    if not collection_name in cache_state:
        log.error(f"collection name {collection_name} does not exist")
        return None, None, None, None, None

    cache_hashes = get_collection_hashes(collection_name, cache_state)
    cache_hashes.reverse()

    stack.push(cache_hashes)
    stack.push(len(cache_hashes))
    return stack, memory, pc, cache_state, cache_accounts


# followed by sha256
def tx_values_to_hash(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: TXVALSHASH")
    log.debug(f"cache state: {cache_state}")
    pc += 1

    tx_hash_ = stack.pop()
    collection_name = stack.pop()

    if not collection_name in cache_state:
        log.error(f"collection name {collection_name} does not exist")
        return None, None, None, None, None
    
    values_to_hash = get_tx_data_to_hash(name=collection_name, cache_state=cache_state, tx_hash_=tx_hash_)
    values_to_hash.reverse()

    stack.push(values_to_hash)
    stack.push(len(values_to_hash))

    return stack, memory, pc, cache_state, cache_accounts


def get_state(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: UPDATESTATE")
    pc += 1

    collection_name = stack.pop()
    if not collection_name in cache_state:
        log.error(f"collection name {collection_name} does not exist")
        return None, None, None, None, None
    
    collection_ref = db.collection(collection_name)
    state_dict = collection_ref.document('state').get().to_dict()

    if state_dict is None:
        log.error(f"state doc for {collection_name}, does not exist")
        return None, None, None, None, None

    if not cache_state[collection_name]['state']['root_hash']:
        log.info("no state cache exists, adding...")
        cache_state[collection_name]['state'] = state_dict

        return stack, memory, pc, cache_state, cache_accounts
    else:
        local_hash = cache_state[collection_name]['state']['root_hash']

        if local_hash == state_dict['root_hash']:
            return stack, memory, pc, cache_state, cache_accounts
        
        else:
            log.error("root hashes don't match")
            return None, None, None, None, None
    

# attempts to update the cache with latest values. Note that we will only need
# to call this function if we do create/delete operations, or plainly just need to confirm state. Most operations i.e.
# checking if a document exists require just the state document
# followed by a jumpif
def update_cache(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: UPDATECACHE")
    pc += 1

    collection_name = stack.pop()

    if not collection_name in cache_state:
        log.error(f"collection name {collection_name}, does not exist")
        return None, None, None, None, None
    
    collection_ref = db.collection(collection_name)
    state_dict = collection_ref.document('state').get().to_dict()

    if state_dict is None:
        log.error(f"state doc for {collection_name}, does not exist")
        return None, None, None, None, None
    
    if not cache_state[collection_name]['state']['root_hash']:
        # no cache exists, proceed with query
        log.info("no cache exists, querying...")
        query = collection_ref.order_by('submitted_on.unix', direction=firestore.Query.ASCENDING)
        results = query.stream()
        cache_state[collection_name]['state'] = state_dict
        for doc in results:
            cache_state[collection_name][doc.id] = doc.to_dict()
    
        return stack, memory, pc, cache_state, cache_accounts
    
    else:
        log.info("cache exists confirming validity...")
        # check if state hashes match
        root_hash = state_dict['root_hash']
        local_hash = cache_state[collection_name]['state']['root_hash']
        
        if local_hash == root_hash:
            log.info("hashes match no need for update")
            return stack, memory, pc, cache_state, cache_accounts
        else:
            get_last_3_state_changes = state_dict['prev_3_states']
            oldest = get_last_3_state_changes['0']
            second = get_last_3_state_changes['1']
            newest = get_last_3_state_changes['2']

            local_oldest = cache_state[collection_name]['state']['prev_3_states']['0']
            local_second = cache_state[collection_name]['state']['prev_3_states']['1']
            local_newest = cache_state[collection_name]['state']['prev_3_states']['2']

            update_attempted = 0

            # try applying delete and create operations until hashes match
            if oldest['tx_hash'] != local_oldest.get('tx_hash', False):
                operation_done = oldest['op'] # can be delete or create

                if operation_done == CREATE:
                    cache_state[collection_name]['temp_'+oldest['tx_hash']] = {
                        'submitted_on': oldest['submitted_on']
                    }

                    local_oldest = oldest
                    update_attempted = 1                    
                elif operation_done == DELETE:
                    if cache_state[collection_name].get('temp_'+oldest['tx_hash'], False):
                        del cache_state[collection_name]['temp_'+oldest['tx_hash']]
                    else:
                        del cache_state[collection_name][oldest['tx_hash']]

                    local_oldest = oldest
                    update_attempted = 1

            if second['tx_hash'] != local_second.get('tx_hash', False):
                operation_done = second['op'] # can be delete or create

                if operation_done == CREATE:
                    cache_state[collection_name]['temp_'+second['tx_hash']] =  {
                        'submitted_on': second['submitted_on']
                    }

                    local_second = second
                    update_attempted = 1
                
                elif operation_done == DELETE:
                    if cache_state[collection_name].get('temp_'+second['tx_hash'], False):
                        del cache_state[collection_name]['temp_'+second['tx_hash']]
                    else:
                        del cache_state[collection_name][second['tx_hash']]

                    local_second = second
                    update_attempted = 1
        
            if newest['tx_hash'] != local_newest.get('tx_hash', False):
                operation_done = newest['op'] # can be delete or create

                if operation_done == CREATE:
                    cache_state[collection_name]['temp_'+newest['tx_hash']] =  {
                        'submitted_on': newest['submitted_on']
                    }
                    local_newest = newest
                    update_attempted = 1

                elif operation_done == DELETE:
                    if cache_state[collection_name].get('temp_'+newest['tx_hash'], False):
                        del cache_state[collection_name]['temp_'+newest['tx_hash']]
                    else:
                        del cache_state[collection_name][newest['tx_hash']]
                    local_newest = newest
                    update_attempted = 1
            

            if update_attempted:
                # since we inserted new elements, sort the dict so as to calculate correct hash
                log.debug(f"cache after prev_state update but before sort: {cache_state}")
                sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1]['submitted_on']['unix'] if 'submitted_on' in item[1] and 'unix' in item[1]['submitted_on'] else Decimal(0))
                log.debug(f"cache after prev_state update after sort: {sorted_tuples}")
                cache_state[collection_name] = {k: v for k, v in sorted_tuples}

                # push all hashes to stack
                cache_hashes = get_collection_hashes(collection_name, cache_state)

                # obey stack law of LIFO(Last in First Out)
                cache_hashes.reverse()

                stack.push(cache_hashes)
                stack.push(len(cache_hashes))

                return stack, memory, pc, cache_state, cache_accounts

            else:
                # final attempt at preventing a full query, get a set of all hashes, perform set difference
                # of local and remote. Time complexity should be O(1) since python uses hash tables for sets

                update_attempted = 0

                remote_ids = set(state_dict['all_tx_hashes'].keys())
                local_ids = set(cache_state[collection_name].keys())
                local_ids.remove('state')
                local_ids.remove('prev_states')

                # in cache but not remote, means a delete happened
                to_delete = local_ids - remote_ids
                if len(to_delete) != 0:
                    for val in to_delete:
                        del cache_state[collection_name][val]
                        update_attempted = 1
                
                # in remote but not in cache, means a create happened
                to_create = remote_ids - local_ids
                if len(to_create) != 0:
                    for val in to_create:
                        cache_state[collection_name]['temp_'+val] = {
                            'submitted_on': state_dict['all_tx_hashes'][val]
                        }
                        update_attempted = 1
                
                if update_attempted:
                    # since we inserted new elements, sort the dict so as to calculate correct hash
                    log.debug(f"cache after prev_state update but before sort: {cache_state}")
                    sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1]['submitted_on']['unix'] if 'submitted_on' in item[1] and 'unix' in item[1]['submitted_on'] else Decimal(0))
                    log.debug(f"cache after prev_state update after sort: {sorted_tuples}")
                    cache_state[collection_name] = {k: v for k, v in sorted_tuples}

                    # push all hashes to stack
                    cache_hashes = get_collection_hashes(collection_name, cache_state)
                    if not cache_hashes:
                        log.error("returned hash list was empty")
                        return None, None, None, None, None

                    # this is to obey the stack law of LIFO(Last in First Out)
                    cache_hashes.reverse()

                    stack.push(cache_hashes)
                    stack.push(len(cache_hashes))

                    return stack, memory, pc, cache_state, cache_accounts

                else:
                    # at this point, query all entries
                    log.info("state changes many, doing full update...")
                    query = collection_ref.order_by('submitted_on', direction=firestore.Query.ASCENDING)
                    results = query.stream()
                    cache_state[collection_name] = {}
                    cache_state[collection_name]['state'] = state_dict
                    for doc in results:
                        cache_state[collection_name][doc.id] = doc.to_dict()
                    

                    local_hash = cache_state[collection_name]['state']['root_hash']

                    if local_hash != root_hash:
                        log.error("hashes don't match after full query")
                        return None, None, None, None, None
                    
                    return stack, memory, pc, cache_state, cache_accounts


# TODO: replace 1634774400000.0 with time.time()
def timestamp_now(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: NOW")
    pc += 1

    stack.push(Decimal('1.6530634936213117e+18'))
    return stack, memory, pc, cache_state, cache_accounts


def swap(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: SWAP")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(a)
    stack.push(b)
    return stack, memory, pc, cache_state, cache_accounts


def create_address(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CADDR")
    pc += 1

    address_name = stack.pop()
    amount = stack.pop()
    cache_accounts[address_name] = amount
    return stack, memory, pc, cache_state, cache_accounts


def delete_address(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DADDR")
    pc += 1

    address_name = stack.pop()
    if address_name in cache_accounts:
        del cache_accounts[address_name]
        return stack, memory, pc, cache_state, cache_accounts
    else:
        log.error("Address does not exist")
        return None, None, None, None, None


def create_entry(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CENTRY")
    pc += 1

    entry_name = stack.pop()

    if entry_name == SELL:
        cache_state[EVENTC[SELL]]['temp'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'tray_no', 'tray_price', 'buyer', 'date', 'section' ]
        tx_hash = ''
        for id in order:
            val = stack.pop()
            if id == 'submitted_on' or id == 'date':
                dt1 = dt.fromtimestamp(int(val), tz=NBO)
                locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")

                cache_state[EVENTC[SELL]]['temp'][id] = {'unix': val, 'locale': locale+', Africa/Nairobi'}

            else:
                cache_state[EVENTC[SELL]]['temp'][id] = val

            if id == 'tx_hash':
                tx_hash = val

        cache_state[EVENTC[SELL]]['temp']['prev_values'] = {}

        # if tx_hash already exists, move to prev field index next, update current
        if tx_hash in cache_state[EVENTC[SELL]]:
            index = 0
            prev_keys = cache_state[EVENTC[SELL]][tx_hash]['prev_values'].keys()
            if prev_keys:
                index = int(max(prev_keys))+1

            temp_dict = cache_state[EVENTC[SELL]][tx_hash]
            cache_state[EVENTC[SELL]]['temp']['prev_values'] = temp_dict['prev_values']
            del temp_dict['prev_values']

            cache_state[EVENTC[SELL]]['temp']['prev_values'][str(index)] = temp_dict
            cache_state[EVENTC[SELL]][tx_hash] = cache_state[EVENTC[SELL]]['temp']
            
        else:
            cache_state[EVENTC[SELL]][tx_hash] = cache_state[EVENTC[SELL]]['temp']
        
        cache_state[EVENTC[SELL]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[SELL]][tx_hash]['submitted_on']
        del cache_state[EVENTC[SELL]]['temp']

        # update the prev_3_states
        subm_on = cache_state[EVENTC[SELL]][tx_hash]['submitted_on']
        cache_state[EVENTC[SELL]]['state']['prev_3_states'] = update_prev_3_states(cache_state[EVENTC[SELL]]['state']['prev_3_states'], subm_on, tx_hash)

    elif entry_name == BUY:
        cache_state[EVENTC[BUY]]['temp'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'item_no', 'item_price', 'item_name', 'date', 'section' ]
        tx_hash = ''
        for id in order:
            val = stack.pop()

            if id == 'submitted_on' or id == 'date':
                dt1 = dt.fromtimestamp(int(val), tz=NBO)
                locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")

                cache_state[EVENTC[BUY]]['temp'][id] = {'unix': val, 'locale': locale+', Africa/Nairobi'}
                
            else:
                cache_state[EVENTC[BUY]]['temp'][id] = val

            if id == 'tx_hash':
                tx_hash = val
        
        cache_state[EVENTC[BUY]]['temp']['prev_values'] = {}

        # if tx_hash already exists, move to prev field index next, update current
        if tx_hash in cache_state[EVENTC[BUY]]:
            index = 0
            prev_keys = cache_state[EVENTC[BUY]][tx_hash]['prev_values'].keys()
            if prev_keys:
                index = int(max(prev_keys))+1

            temp_dict = cache_state[EVENTC[BUY]][tx_hash]
            cache_state[EVENTC[BUY]]['temp']['prev_values'] = temp_dict['prev_values']
            del temp_dict['prev_values']

            cache_state[EVENTC[BUY]]['temp']['prev_values'][str(index)] = temp_dict
            cache_state[EVENTC[BUY]][tx_hash] = cache_state[EVENTC[BUY]]['temp']
            
        else:
            cache_state[EVENTC[BUY]][tx_hash] = cache_state[EVENTC[BUY]]['temp']

        cache_state[EVENTC[BUY]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[BUY]][tx_hash]['submitted_on']
        del cache_state[EVENTC[BUY]]['temp']

        # update the prev_3_states
        subm_on = cache_state[EVENTC[BUY]][tx_hash]['submitted_on']
        cache_state[EVENTC[BUY]]['state']['prev_3_states'] = update_prev_3_states(cache_state[EVENTC[BUY]]['state']['prev_3_states'], subm_on, tx_hash)

    elif entry_name == DS:
        cache_state[EVENTC[DS]]['temp'] = {}
        order = [ 'submitted_on', 'by', 'image_url', 'image_id', 'reason', 'tx_hash', 'number', 'date', 'section', 'location']
        tx_hash = ''
        for id in order:
            val = stack.pop()
            if id == 'submitted_on' or id == 'date':
                dt1 = dt.fromtimestamp(int(val), tz=NBO)
                locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")

                cache_state[EVENTC[DS]]['temp'][id] = {'unix': val, 'locale': locale+', Africa/Nairobi'}
                
            else:
                cache_state[EVENTC[DS]]['temp'][id] = val

            if id == 'tx_hash':
                tx_hash = val
            
        
        cache_state[EVENTC[BUY]]['temp']['prev_values'] = {}

        # if tx_hash already exists, move to prev field index next, update current
        if tx_hash in cache_state[EVENTC[BUY]]:
            index = 0
            prev_keys = cache_state[EVENTC[BUY]][tx_hash]['prev_values'].keys()
            if prev_keys:
                index = int(max(prev_keys))+1

            temp_dict = cache_state[EVENTC[BUY]][tx_hash]
            cache_state[EVENTC[BUY]]['temp']['prev_values'] = temp_dict['prev_values']
            del temp_dict['prev_values']

            cache_state[EVENTC[BUY]]['temp']['prev_values'][str(index)] = temp_dict
            cache_state[EVENTC[BUY]][tx_hash] = cache_state[EVENTC[BUY]]['temp']
            
        else:
            cache_state[EVENTC[BUY]][tx_hash] = cache_state[EVENTC[BUY]]['temp']
        
        cache_state[EVENTC[DS]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[DS]][tx_hash]['submitted_on']
        del cache_state[EVENTC[DS]]['temp']
        
        # update the prev_3_states
        subm_on = cache_state[EVENTC[DS]][tx_hash]['submitted_on']
        cache_state[EVENTC[DS]]['state']['prev_3_states'] = update_prev_3_states(cache_state[EVENTC[DS]]['state']['prev_3_states'], subm_on, tx_hash)


    elif entry_name == EGGS:
        cache_state[EVENTC[EGGS]]['temp'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'a1', 'a2', 'b1', 'b2', 'c1', 'c2', 'broken', 'house', 'date', 'trays_collected']
        tx_hash = ''
        for id in order:
            val = stack.pop()
            if id == 'submitted_on' or id == 'date':
                dt1 = dt.fromtimestamp(int(val), tz=NBO)
                locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")
                cache_state[EVENTC[EGGS]]['temp'][id] = {'unix': val, 'locale': locale+', Africa/Nairobi'}
                
            else:
                cache_state[EVENTC[EGGS]]['temp'][id] = val

            if id == 'tx_hash':
                tx_hash = val
        

        cache_state[EVENTC[EGGS]]['temp']['prev_values'] = {}

        # if tx_hash already exists, move to prev field index next, update current
        if tx_hash in cache_state[EVENTC[EGGS]]:
            index = 0
            prev_keys = cache_state[EVENTC[EGGS]][tx_hash]['prev_values'].keys()
            if prev_keys:
                index = int(max(prev_keys))+1

            temp_dict = cache_state[EVENTC[EGGS]][tx_hash]
            cache_state[EVENTC[EGGS]]['temp']['prev_values'] = temp_dict['prev_values']
            del temp_dict['prev_values']

            cache_state[EVENTC[EGGS]]['temp']['prev_values'][str(index)] = temp_dict
            cache_state[EVENTC[EGGS]][tx_hash] = cache_state[EVENTC[EGGS]]['temp']
            
        else:
            cache_state[EVENTC[EGGS]][tx_hash] = cache_state[EVENTC[EGGS]]['temp']

        cache_state[EVENTC[EGGS]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[EGGS]][tx_hash]['submitted_on']
        del cache_state[EVENTC[EGGS]]['temp']

        # update the prev_3_states
        subm_on = cache_state[EVENTC[EGGS]][tx_hash]['submitted_on']
        cache_state[EVENTC[EGGS]]['state']['prev_3_states'] = update_prev_3_states(cache_state[EVENTC[EGGS]]['state']['prev_3_states'], subm_on, tx_hash)


    elif entry_name == TRADE:
        cache_state[EVENTC[TRADE]]['temp'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'from', 'to', 'purchase_hash', 'sale_hash', 'amount', 'date']
        tx_hash = ''
        for id in order:
            val = stack.pop()

            if id == 'submitted_on' or id == 'date':
                dt1 = dt.fromtimestamp(int(val), tz=NBO)
                locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")

                cache_state[EVENTC[TRADE]]['temp'][id] = {'unix': val, 'locale': locale+', Africa/Nairobi'}
                
            else:
                cache_state[EVENTC[TRADE]]['temp'][id] = val

            if id == 'tx_hash':
                tx_hash = val
        
        cache_state[EVENTC[TRADE]]['temp']['prev_values'] = {}

        # if tx_hash already exists, move to prev field index next, update current
        if tx_hash in cache_state[EVENTC[TRADE]]:
            index = 0
            prev_keys = cache_state[EVENTC[TRADE]][tx_hash]['prev_values'].keys()
            if prev_keys:
                index = int(max(prev_keys))+1

            temp_dict = cache_state[EVENTC[TRADE]][tx_hash]
            cache_state[EVENTC[TRADE]]['temp']['prev_values'] = temp_dict['prev_values']
            del temp_dict['prev_values']

            cache_state[EVENTC[TRADE]]['temp']['prev_values'][str(index)] = temp_dict
            cache_state[EVENTC[TRADE]][tx_hash] = cache_state[EVENTC[TRADE]]['temp']
            
        else:
            cache_state[EVENTC[TRADE]][tx_hash] = cache_state[EVENTC[TRADE]]['temp']

        cache_state[EVENTC[TRADE]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[TRADE]][tx_hash]['submitted_on']
        del cache_state[EVENTC[TRADE]]['temp']

        # update the prev_3_states
        subm_on = cache_state[EVENTC[TRADE]][tx_hash]['submitted_on']
        cache_state[EVENTC[TRADE]]['state']['prev_3_states'] = update_prev_3_states(cache_state[EVENTC[TRADE]]['state']['prev_3_states'], subm_on, tx_hash)

    else:
        log.error("Invalid entry")
        return None, None, None, None, None
    
    log.debug(f'Entry added: {cache_state}')
    
    return stack, memory, pc, cache_state, cache_accounts


def delete_entry(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DENTRY")
    pc += 1

    tx_hash = stack.pop()
    collection_name = stack.pop()

    if collection_name in cache_state:
        if tx_hash in cache_state[collection_name]:
            dt1 = dt.fromtimestamp(time.time(), tz=NBO)
            locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")

            cache_deleted[tx_hash] = {
                collection: collection_name,
                entry: cache_state[collection_name][tx_hash],
                submitted_on: {'unix': time.time(), 'locale': locale+', Africa/Nairobi'},
                by: memory.get('user', 'null')
            }
            del cache_state[collection_name][tx_hash]
            return stack, memory, pc, cache_state, cache_accounts
    
    log.error(f"collection name: {collection_name} or tx_hash: {tx_hash} does not exist")
    return None, None, None, None, None


def prep_finalise_data(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: PREPFINALISE")

    # everytime create/delete doc is called, collection name is pushed to stack
    # at this point, the stack should only have collection names
    collection_names = set(stack.get_stack())
    stack.clear_stack()
    if not stack.is_stack_empty():
        return None, None, None, None, None

    last_jump = pc+2
    jump_dest = pc+7
    last_jump_2 = jump_dest
    jump_dest_2 = last_jump_2+6
    stack.push(0) # signal first loop is done
    for name in collection_names:
        stack.push(name)
        i = 0
        for key in cache_state[name]:
            if key != 'state' and key != 'prev_states':
                stack.push(cache_state[name][key]['tx_hash'])
                i += 1

        stack.push(i)
    
    stack.push(0) # Signals second loop is done

    for name in collection_names:
        hashes = ''
        '''
        sales: section, date = { unix, string }, buyer, tray_price, tray_no, tx_hash, by
         submitted_on = { unix, string }, local_nonce, global_nonce
        
        purchases: tx_hash, item_name, item_no, item_price, date = { unix, string }, by, section,
         submitted_on = { unix, string }, local_nonce, global_nonce
        
        dead_sick: tx_hash, number, date = { unix, string }, by, section, location, reason, image_id, image_url
         submitted_on = { unix, string }, local_nonce, global_nonce
        
        eggs_collected: tx_hash, a1, a2, b1, b2, c1, c2, broken, house, date = { unix, string }, by, trays_collected
         submitted_on = { unix, string }, local_nonce, global_nonce
        
        trades: tx_hash, from, to, date = { unix, string }, sale_hash, purchase_hash, by,
         submitted_on = { unix, string }, local_nonce, global_nonce, amount

        '''
        is_empty = 1

        for key in cache_state[name]:
            if key != 'state' and key != 'prev_states':
                # get all values in dict - hash
                # hash them
                # if hashed != tx_hash
                # hashes in tx don't match
                # return None, None, None, None, None
                is_empty = 0
                stack.push(pc+2) # location to return to incase of a jump
                stack.push(name)
                stack.push(key)
                if name == 'sales':
                    stack.push(cache_state[name][key]['buyer'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(cache_state[name][key]['section'])

                    total_prev_values = 0
                    if cache_state[name][key]['prev_values']:
                        for in_key in cache_state[name][key]['prev_values']:
                            total_prev_values += 1
                            stack.push(cache_state[name][key]['prev_values'][in_key])
                    
                    stack.push(3+total_prev_values)
                elif name == 'purchases':
                    stack.push(cache_state[name][key]['item_name'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(cache_state[name][key]['section'])

                    total_prev_values = 0
                    if cache_state[name][key]['prev_values']:
                        for in_key in cache_state[name][key]['prev_values']:
                            total_prev_values += 1
                            stack.push(cache_state[name][key]['prev_values'][in_key])
                    
                    stack.push(3+total_prev_values)
                elif name == 'dead_sick':
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(cache_state[name][key]['section'])
                    stack.push(cache_state[name][key]['location'])

                    total_prev_values = 0
                    if cache_state[name][key]['prev_values']:
                        for in_key in cache_state[name][key]['prev_values']:
                            total_prev_values += 1
                            stack.push(cache_state[name][key]['prev_values'][in_key])
                    
                    stack.push(3+total_prev_values)
                elif name == 'eggs_collected':
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    
                    total_prev_values = 0
                    if cache_state[name][key]['prev_values']:
                        for in_key in cache_state[name][key]['prev_values']:
                            total_prev_values += 1
                            stack.push(cache_state[name][key]['prev_values'][in_key])
                    
                    stack.push(1+total_prev_values)
                elif name == 'trades':
                    stack.push(cache_state[name][key]['amount'])
                    stack.push(cache_state[name][key]['from'])
                    stack.push(cache_state[name][key]['to'])
                    stack.push(cache_state[name][key]['sale_hash'])
                    stack.push(cache_state[name][key]['purchase_hash'])
                    # trades will always produce a unique hash since date == current timestamp
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])

                    stack.push(5)
                else:
                    log.error("collection name invalid")
                    return None, None, None, None, None
        
        if is_empty:
            pc += 2
        else:
            pc += 1

    return stack, memory, pc, cache_state, cache_accounts


def calculate_state_root(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CALCSTATE")
    pc += 1

    collection_name = stack.pop()
    if not collection_name in cache_state:
        log.error(f"collection name {collection_name} does not exist")
        return None, None, None, None, None
    
    for tx in cache_state[collection_name]:
        pass




# each week and month is represented by a timestamp
# month is current_timestamp+30days, week is current_timestamp+7days
def initialise():
    print("initialising...")
    all_collections = []
    for name in cache_state:
        all_collections.append(name)
        collection_ref = db.collection(name)
        state = cache_state[name]['state']

        if name == 'eggs_collected':
            state['total_eggs'] = 0
            sections = ['a1','a2', 'b1', 'b2', 'c1', 'c2', 'broke', 'house']
            for sec in sections:
                state[f'total_eggs_{sec}'] = 0

            state['trays_collected_to_timestamp'] = {'0': '0,0'}
            state['diff_trays_to_exact'] = {'0': '0,0'} # 0 represents unix 0
            state['week_trays_and_exact'] = {'0': {'trays_collected': '0,0', 'exact': '0,0'}} # 0 represents timestamp week 0
            state['month_trays_and_exact'] = {'0': {'trays_collected': '0,0', 'exact': '0,0'}} # 0 represents month 0
            state['change_week'] = {'0': {'change_trays_collected': 0, 'change_exact': 0 }} # 0 represents (week 0 - week 0), 1 will represent (week 1 - week 0)
            state['change_month'] = {'0': {'change_trays_collected': 0, 'change_exact': 0 }} # 0 represents (month 0 - month 0), 1 will represent (month 1 - month 0)

        elif name == 'sales':
            state['total_sales'] = 0
            state['total_earned'] = 0
            state['total_trays_sold'] = 0
            sections = ['thikafarmers', 'other', 'cakes', 'duka']
            for sec in sections:
                state[f'total_earned_{sec}'] = 0
                state[f'total_trays_sold_{sec}'] = 0
            # everytime there is a new buyer, we will add a new field total_earned_other_buyer_name

            state['week_trays_sold_earned'] = {'0': {
                'trays_sold': 0,
                'earned': 0,
                f'earned_{sections[0]}': 0,
                f'earned_{sections[1]}': 0,
                f'earned_{sections[2]}': 0,
                f'earned_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'trays_sold_{sections[0]}': 0,
                f'trays_sold_{sections[1]}': 0,
                f'trays_sold_{sections[2]}': 0,
                f'trays_sold_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }
            state['month_trays_sold_earned'] = {'0': {
                'trays_sold': 0,
                'earned': 0,
                f'earned_{sections[0]}': 0,
                f'earned_{sections[1]}': 0,
                f'earned_{sections[2]}': 0,
                f'earned_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'trays_sold_{sections[0]}': 0,
                f'trays_sold_{sections[1]}': 0,
                f'trays_sold_{sections[2]}': 0,
                f'trays_sold_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }
            state['change_week'] = {'0': {
                'change_trays_sold': 0,
                'change_earned': 0,
                f'change_earned_{sections[0]}': 0,
                f'change_earned_{sections[1]}': 0,
                f'change_earned_{sections[2]}': 0,
                f'change_earned_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'change_trays_sold_{sections[0]}': 0,
                f'change_trays_sold_{sections[1]}': 0,
                f'change_trays_sold_{sections[2]}': 0,
                f'change_trays_sold_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }
            state['change_month'] = {'0': {
                'change_trays_sold': 0,
                'change_earned': 0,
                f'change_earned_{sections[0]}': 0,
                f'change_earned_{sections[1]}': 0,
                f'change_earned_{sections[2]}': 0,
                f'change_earned_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'change_trays_sold_{sections[0]}': 0,
                f'change_trays_sold_{sections[1]}': 0,
                f'change_trays_sold_{sections[2]}': 0,
                f'change_trays_sold_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }

        elif name == 'purchases':
            state['total_purchases'] = 0
            state['total_spent'] = 0
            state['total_items_bought'] = 0
            sections = ['feeds', 'drugs', 'other', 'purity']
            for sec in sections:
                state[f'total_spent_{sec}'] = 0
            # everytime there is a new buyer, we will add a new field total_earned_other_buyer_name

            state['week_items_bought_spent'] = {'0': {
                'items_bought': 0,
                'spent': 0,
                f'spent_{sections[0]}': 0,
                f'spent_{sections[1]}': 0,
                f'spent_{sections[2]}': 0,
                f'spent_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'items_bought_{sections[0]}': 0,
                f'items_bought_{sections[1]}': 0,
                f'items_bought_{sections[2]}': 0,
                f'items_bought_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }
            state['month_items_bought_spent'] = {'0': {
                'items_bought': 0,
                'spent': 0,
                f'spent_{sections[0]}': 0,
                f'spent_{sections[1]}': 0,
                f'spent_{sections[2]}': 0,
                f'spent_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'items_bought_{sections[0]}': 0,
                f'items_bought_{sections[1]}': 0,
                f'items_bought_{sections[2]}': 0,
                f'items_bought_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }
            state['change_week'] = {'0': {
                'change_items_bought': 0,
                'change_spent': 0,
                f'change_spent_{sections[0]}': 0,
                f'change_spent_{sections[1]}': 0,
                f'change_spent_{sections[2]}': 0,
                f'change_spent_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'change_items_bought_{sections[0]}': 0,
                f'change_items_bought_{sections[1]}': 0,
                f'change_items_bought_{sections[2]}': 0,
                f'change_items_bought_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }
            state['change_month'] = {'0': {
                'change_items_bought': 0,
                'change_spent': 0,
                f'change_spent_{sections[0]}': 0,
                f'change_spent_{sections[1]}': 0,
                f'change_spent_{sections[2]}': 0,
                f'change_spent_{sections[3]}': 0, # earned_other_buyer_name added whenever
                f'change_items_bought_{sections[0]}': 0,
                f'change_items_bought_{sections[1]}': 0,
                f'change_items_bought_{sections[2]}': 0,
                f'change_items_bought_{sections[3]}': 0, # earned_other_buyer_name added whenever
                }
            }

        elif name == 'dead_sick':
            state['total_dead'] = 0
        
        elif name == 'trades':
            state['balances'] = cache_accounts


        collection_ref.document('state').set(state)
        collection_ref.document('prev_states').set({'0': state })
        print(name, "added state")
    
    global_state_ref = db.collection('world_state')
    world_state = {
        f'root_{all_collections[0]}': '',
        f'root_{all_collections[1]}': '',
        f'root_{all_collections[2]}': '',
        f'root_{all_collections[3]}': '',
        f'root_{all_collections[4]}': '',
        'week_laying_percent': {'0': {}},
        'month_laying_percent': {'0': {}},
        'week_profit': {'0': 0 },
        'month_profit': {'0': 0 },
        'available_to_withdraw': {},  # users will be added here once trade state is updated with an account
        'net_user_income': {'total': 0}, # this will never be final i.e. a change could happen in the state after a withdraw leading to negative amount
        'age_of_birds': {'start_date': {'unix': 0, 'locale': ''}, 'age': {'unix': 0, 'years': 0, 'months': 0, 'weeks': 0 }}
    }
    sections = ['total', 'a1','a2', 'b1', 'b2', 'c1', 'c2', 'house']
    for sec in sections:
        world_state['week_laying_percent']['0'][f'{sec}'] = 0
        world_state['month_laying_percent']['0'][f'{sec}'] = 0
    
    global_state_ref.document('main').set(world_state)
    collection_ref.document('prev_states').set({'0': state })


inst_mapping = {
    str(PUSH): push,
    str(DUP): dup,
    str(ADD): add,
    str(MUL): mul,
    str(SUB): sub,
    str(DIV): div,
    str(EQ): eq,
    str(SWAP): swap,
    str(ISZERO): is_zero,
    str(STOP): stop,
    str(TXVALSHASH): tx_values_to_hash,
    str(COLLHASH): collection_hashes_to_hash,
    str(ROOTHASH): root_hash,
    str(SHA256): sha256,
    str(UPDATECACHE): update_cache,
    str(STATE): get_state,
    str(PREPFINALISE): prep_finalise_data,
    str(CENTRY): create_entry,
    str(CADDR): create_address,
    str(DADDR): delete_address,
    str(DENTRY): delete_entry,
    str(NOW): timestamp_now
}


'''
Only sell events introduce money to the vm
{create entry}
sell y trays to buyer x of section k at price of s on p, by f
PUSH y
PUSH s
MUL
PUSH 1
DUP
PUSH k
CADDR
PUSH f
CADDR
PUSH k // section
PUSH p // date
PUSH x // buyer
PUSH s // tray_price
PUSH y // tray_no
PUSH 5
DUP
PUSH 5
sha256 // tx_hash
PUSH f // by
NOW    // submitted_on
PUSH EVENT
CENTRY

buy y objects called x of section k at price of s on p, by f
PUSH y
PUSH s
MUL
PUSH 1
DUP
PUSH k
CADDR
PUSH f
CADDR
PUSH k // section
PUSH p // date
PUSH x // item name
PUSH s // item_price
PUSH y // item_no
PUSH 5
DUP
PUSH 5
sha256 // tx_hash
PUSH f // by
NOW    // submitted_on
PUSH EVENT
CENTRY

trade from y to x k amount on p, by f
PUSH date
PUSH purchase_hash
PUSH sales_hash
PUSH x
PUSH y
PUSH amount
PUSH 6
DUP
PUSH 6
sha256 // tx_hash
PUSH f // by
NOW    // submitted_on
PUSH y
BALANCE
PUSH k
SUB
PUSH 0
LT
PUSH EVENT
SWAP
CENTRY // checks if balance is ok


eggs y objects called x of section k at price of s on p, by f
PUSH y
PUSH s
MUL
PUSH 1
DUP
PUSH k
CADDR
PUSH f
CADDR
PUSH k // section
PUSH p // date
PUSH x // buyer
PUSH s // tray_price
PUSH y // tray_no
PUSH 5
DUP
PUSH 5
sha256 // tx_hash
PUSH f // by
NOW    // submitted_on
PUSH EVENT
CENTRY


y chickens are x(section) from k(location) on p cause of r image being i u, by f
PUSH k // location
PUSH x // section
PUSH p // date
PUSH y // number
PUSH 4
DUP
PUSH 4
sha256 // tx_hash
PUSH r // reason
PUSH i // image_id
PUSH u // image_url
PUSH f // by
NOW    // submitted_on
PUSH EVENT
CENTRY





{after all create/delete operations execute this instructions}
PREPFINALISE
sha256
TXHASH
EQ
EXITLOOP
JUMPIF
sha256
SWAP
ROOTHASH
EQ
EXITLOOP
JUMPIF
STOP

'''
#TODO Have 2 opcodes, JUMPIF(after analysis, each jumpif in the code should have a destination map to it, to signify end of jumped
# to destination, ENDJUMP opcode called, doesn't read anything from stack but also analysis contains the jumpif location+1, 
# changes program counter to that)
# TODO At the end of main function execution, have STOP(reads last value in stack(should contain only one element) if stack is empty)
# an error occured. After the stop, include all jump destination code in order of when jumpif was called


#TODO break this into steps:
# final_call() pushes 1,
# pops final call, pushes at end, get_collection_name_and_total_txs_in_it(pushes, coll_name, tx_ids, total_txs),
# get_tx(pops num of elements, decreases by 1, if 0, push end_inner_loop_signal else pushes back, pushes tx required data & num),
# hash them, compare, if true, inner_loop check if done jump_to get_collection_name else jump_to next tx
# followed by jumpif
