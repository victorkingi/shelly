# Instructions
from functools import reduce
from decimal import *
from firebase_admin import credentials
from firebase_admin import firestore
from datetime import datetime as dt
from dateutil import tz
import time
import sys
import re

from opcodes import Opcodes
from util import *
from log_ import log
from constants import *

import time
import hashlib
import firebase_admin

getcontext().traps[FloatOperation] = True
TWOPLACES = Decimal(10) ** -2 

other = 'other'
starting_birds_no = Decimal(500)

cred = credentials.Certificate("core101-3afde-firebase-adminsdk-sxm20-194a475b51.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

NBO = tz.gettz('Africa/Nairobi')

cache_state = {
    'world_state': {
        'main': {},
        'prev_states': {}
    },
    'sales': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {}
        },
        'prev_states': {}
    },
    'purchases': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {}
        },
        'prev_states': {}
    },
    'eggs_collected': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {}
        },
        'prev_states': {}
    },
    'dead_sick': {
       'state': {
            'root_hash': '',
            'all_tx_hashes': {}
        },
        'prev_states': {}
    },
    'trades': {
        'state': {
            'root_hash': '',
            'all_tx_hashes': {}
        },
        'prev_states': {}
    }
}
cache_accounts = {'BLACK_HOLE': Decimal(MAX_EMAX), 'ANNE': Decimal(4000) }
cache_deleted = {} # no need to keep track of this as entries are only dumped into it
cache_ui_txs = {}
cache_verification_data = {}
cache_dashboard_data = {}


def push(elem=None, stack=None, memory=None, pc=None, analysed=None):
    prev_type = type(elem)
    log.debug(f"{pc}: PUSH {elem}, {type(elem)}")
    pc += 2

    if isinstance(elem, float) or isinstance(elem, int):
        elem = Decimal(str(elem))
        log.debug(f"converted from {prev_type} to {type(elem)}")

    if isinstance(elem, Decimal) or isinstance(elem, str):
        stack.push(elem)
        return stack, memory, pc, cache_state, cache_accounts
    else:
        log.error(f"Attempted to push not a str or a decimal type, {type(elem)}")
        return None, None, None, None, None

# does not return the element poped
def pop(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: POP")
    pc += 1

    stack.pop()
    
    return stack, memory, pc, cache_state, cache_accounts


def add(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: ADD")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(b + a)
    
    return stack, memory, pc, cache_state, cache_accounts


def lt(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: LT")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(Decimal(1) if b < a else Decimal(0))
    
    return stack, memory, pc, cache_state, cache_accounts


def gt(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: GT")
    pc += 1

    a = stack.pop()
    b = stack.pop()
    stack.push(Decimal(1) if b > a else Decimal(0))
    
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
            'world_state': {
                'main': {},
                'prev_states': {}
            },
            'sales': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {}
                },
                'prev_states': {}
            },
            'purchases': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {}
                },
                'prev_states': {}
            },
            'eggs_collected': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {}
                },
                'prev_states': {}
            },
            'dead_sick': {
            'state': {
                    'root_hash': '',
                    'all_tx_hashes': {}
                },
                'prev_states': {}
            },
            'trades': {
                'state': {
                    'root_hash': '',
                    'all_tx_hashes': {}
                },
                'prev_states': {}
            }
        }
        empty_accounts = {'BLACK_HOLE': Decimal(MAX_EMAX), 'ANNE': Decimal(4000) }

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


def mstore(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: MSTORE")
    pc += 1

    elem = stack.pop()

    is_valid_hash = re.search("^[a-f0-9]{64}$", elem)
    event_keys = EVENTC.keys()
    if is_valid_hash:
        memory['SHA256'] = elem
    elif elem in event_keys:
        memory['EVENT'] = elem
    else:
        log.error("storage location not assigned yet")
        return None, None, None, None, None

    return stack, memory, pc, cache_state, cache_accounts


def mload(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: MLOAD")
    pc += 1

    key = stack.pop()
    stack.push(memory[key])

    return stack, memory, pc, cache_state, cache_accounts

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


def panic(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: PANIC")
    pc += 1

    val = stack.pop()

    if val:
        log.error("Program exited with panic")
        return None, None, None, None, None

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


def jumpif(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: JUMPIF")
    pc += 1
    temp = int(pc)

    a = stack.pop()
    pc = analysed[str(temp-1)] if str(temp-1) in analysed and a == Decimal(1) else pc

    if str(temp-1) not in analysed:
        log.error(f"Selected jump destination does not exist, {temp-1}, analysed: {analysed}")
        return None, None, None, None, None
    
    return stack, memory, pc, cache_state, cache_accounts


def jumpdes(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: JUMPDEST")
    pc += 1
    
    return stack, memory, pc, cache_state, cache_accounts


def get_state(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: UPDATESTATE")
    pc += 1

    collection_name = stack.pop()
    
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
    
    collection_ref = db.collection(collection_name)

    if collection_name == 'world_state':
        state_dict = collection_ref.document('main').get().to_dict()
        cache_state['world_state']['main'] = state_dict
        state_dict = collection_ref.document('prev_states').get().to_dict()
        cache_state['world_state']['prev_states'] = state_dict
        map_nested_dicts_modify(cache_state, lambda v: Decimal(f'{v}') if isinstance(v, float) or isinstance(v, int) else v)
        log.debug("Updated main state")
        return stack, memory, pc, cache_state, cache_accounts


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
        
        if collection_name == EVENTC[TRADE]:
            for user in state_dict['balances']:
                cache_accounts[user] = Decimal(str(state_dict['balances'][user]))

        map_nested_dicts_modify(cache_state, lambda v: Decimal(f'{v}') if isinstance(v, float) or isinstance(v, int) else v)
        map_nested_dicts_modify(cache_accounts, lambda v: Decimal(f'{v}') if isinstance(v, float) or isinstance(v, int) else v)

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
            # get a set of all hashes, perform set difference of local and remote.
            # Time complexity should be O(1) since python uses hash tables for sets

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
                map_nested_dicts_modify(cache_state, lambda v: Decimal(f'{v}') if isinstance(v, float) or isinstance(v, int) else v)
                map_nested_dicts_modify(cache_accounts, lambda v: Decimal(f'{v}') if isinstance(v, float) or isinstance(v, int) else v)

                log.info("New entries added or deleted on query")
                
                return stack, memory, pc, cache_state, cache_accounts
            else:
                log.info("No new entries found for update, proceeding...")
                return stack, memory, pc, cache_state, cache_accounts


def timestamp_now(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: NOW")
    pc += 1

    stack.push(Decimal(f'{time.time()}'))
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
    if address_name not in cache_accounts:
        cache_accounts[address_name] = Decimal(0)
    
    return stack, memory, pc, cache_state, cache_accounts


def delete_address(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DADDR")
    pc += 1

    address_name = stack.pop()
    del cache_accounts[address_name]
    return stack, memory, pc, cache_state, cache_accounts


def create_entry(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CENTRY")
    pc += 1

    entry_name = stack.pop()
    entry_hash = ''
    is_replaced = False

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
                entry_hash = tx_hash

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
            is_replaced = True
            
        else:
            cache_state[EVENTC[SELL]][tx_hash] = cache_state[EVENTC[SELL]]['temp']
        
        cache_state[EVENTC[SELL]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[SELL]][tx_hash]['submitted_on']
        del cache_state[EVENTC[SELL]]['temp']

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
                entry_hash = tx_hash
        
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
            is_replaced = True
            
        else:
            cache_state[EVENTC[BUY]][tx_hash] = cache_state[EVENTC[BUY]]['temp']

        cache_state[EVENTC[BUY]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[BUY]][tx_hash]['submitted_on']
        del cache_state[EVENTC[BUY]]['temp']

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
                entry_hash = tx_hash
            
        
        cache_state[EVENTC[DS]]['temp']['prev_values'] = {}

        # if tx_hash already exists, move to prev field index next, update current
        if tx_hash in cache_state[EVENTC[DS]]:
            index = 0
            prev_keys = cache_state[EVENTC[DS]][tx_hash]['prev_values'].keys()
            if prev_keys:
                index = int(max(prev_keys))+1

            temp_dict = cache_state[EVENTC[DS]][tx_hash]
            cache_state[EVENTC[DS]]['temp']['prev_values'] = temp_dict['prev_values']
            del temp_dict['prev_values']

            cache_state[EVENTC[DS]]['temp']['prev_values'][str(index)] = temp_dict
            cache_state[EVENTC[DS]][tx_hash] = cache_state[EVENTC[DS]]['temp']
            is_replaced = True
            
        else:
            cache_state[EVENTC[DS]][tx_hash] = cache_state[EVENTC[DS]]['temp']
        
        cache_state[EVENTC[DS]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[DS]][tx_hash]['submitted_on']
        del cache_state[EVENTC[DS]]['temp']
        
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
                entry_hash = tx_hash
        

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
            is_replaced = True
            
        else:
            cache_state[EVENTC[EGGS]][tx_hash] = cache_state[EVENTC[EGGS]]['temp']

        cache_state[EVENTC[EGGS]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[EGGS]][tx_hash]['submitted_on']
        del cache_state[EVENTC[EGGS]]['temp']

    elif entry_name == TRADE:
        cache_state[EVENTC[TRADE]]['temp'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'from', 'to', 'purchase_hash', 'sale_hash', 'amount', 'date', 'reason']
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
                entry_hash = tx_hash
        
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
            is_replaced = True
            
        else:
            cache_state[EVENTC[TRADE]][tx_hash] = cache_state[EVENTC[TRADE]]['temp']

        cache_state[EVENTC[TRADE]]['state']['all_tx_hashes'][tx_hash] = cache_state[EVENTC[TRADE]][tx_hash]['submitted_on']
        del cache_state[EVENTC[TRADE]]['temp']

    if not is_replaced:
        log.info(f'Entry added, collection: {EVENTC[entry_name]}, {cache_state[EVENTC[entry_name]][entry_hash]}')
        memory['TOTALCREATES'] += 1
        if EVENTC[entry_name] in memory['ADDED']:
            memory['ADDED'][EVENTC[entry_name]] += 1
        else:
            memory['ADDED'][EVENTC[entry_name]] = 1
    else:
        log.info(f'Entry replaced, collection: {EVENTC[entry_name]}, {cache_state[EVENTC[entry_name]][entry_hash]}')
        memory['TOTALCREATES'] += 1
        memory['TOTALREPLACE'] += 1
        if EVENTC[entry_name] in memory['REPLACED']:
            memory['REPLACED'][EVENTC[entry_name]]['num'] += 1
            memory['REPLACED'][EVENTC[entry_name]]['hashes'].append(entry_hash)
        else:
            memory['REPLACED'][EVENTC[entry_name]] = {'num': 1, 'hashes': [entry_hash]}
        
        if EVENTC[entry_name] in memory['ADDED']:
            memory['ADDED'][EVENTC[entry_name]] += 1
        else:
            memory['ADDED'][EVENTC[entry_name]] = 1
    
    return stack, memory, pc, cache_state, cache_accounts


def delete_entry(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DENTRY")
    pc += 1

    tx_hash = stack.pop()
    collection_name = stack.pop()

    dt1 = dt.fromtimestamp(time.time(), tz=NBO)
    locale = dt1.strftime("%m/%d/%Y, %H:%M:%S")

    cache_deleted[tx_hash] = {
        collection: collection_name,
        entry: cache_state[collection_name][tx_hash],
        submitted_on: {'unix': Decimal(time.time()), 'locale': locale+', Africa/Nairobi'},
        by: memory.get('user', 'null')
    }
    del cache_state[collection_name][tx_hash]
    
    log.info(f"entry deleted in collection {collection_name}, id: {tx_hash}")
    memory['TOTALDELETES'] += 1

    if EVENTC[entry_name] in memory['DELETES']:
        memory['DELETES'][EVENTC[entry_name]]['num'] += 1
        memory['DELETES'][EVENTC[entry_name]]['hashes'].append(tx_hash)
    else:
        memory['DELETES'][EVENTC[entry_name]] = {'num': 1, 'hashes': [tx_hash]}

    return stack, memory, pc, cache_state, cache_accounts


def full_calculate_new_state(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CALCSTATE")
    pc += 1

    collection_name = stack.pop()

    week_in_seconds = 7 * 24 * 60 * 60
    week_in_seconds = Decimal(week_in_seconds)
    month_in_seconds = 28 * 24 * 60 * 60
    month_in_seconds = Decimal(month_in_seconds)

    log.debug(f"cache after prev_state update but before sort: {cache_state[collection_name]}")
    sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1]['date']['unix'] if 'date' in item[1] and 'unix' in item[1]['date'] else Decimal(0))
    log.debug(f"cache after prev_state update after sort: {sorted_tuples}")
    cache_state[collection_name] = {k: v for k, v in sorted_tuples}

    is_first = True
    next_week = Decimal(0)
    next_month = Decimal(0)
    i = 0
    
    if collection_name == EVENTC[TRADE]:
        cache_state[collection_name]['state']['balances'] = {}
        for user in cache_accounts:
            if user == 'BLACK_HOLE':
                cache_state[collection_name]['state']['balances'][user] = Decimal(MAX_EMAX)
                continue
            elif user == 'ANNE':
                cache_state[collection_name]['state']['balances'][user] = Decimal(4000)
            else:    
                cache_state[collection_name]['state']['balances'][user] = Decimal(0) # initialise all

            for id in cache_state[collection_name]:
                if id == 'state' or id == 'prev_states':
                    continue
            
                tx = cache_state[collection_name][id]

                if tx['to'] == user:
                    cache_state[collection_name]['state']['balances'][user] += Decimal(str(tx['amount']))
                        
                elif tx['from'] == user:
                    cache_state[collection_name]['state']['balances'][user] -= Decimal(str(tx['amount']))
            
            if cache_state[collection_name]['state']['balances'][user] != cache_accounts[user]:
                log.error(f"balances do not match for address {user}, state: {cache_state[collection_name]['state']['balances'][user]}, acc: {cache_accounts[user]}")
                return None, None, None, None, None
            
            if cache_state[collection_name]['state']['balances'][user] < Decimal(0):
                log.error(f"address {user} balance is negative {cache_state[collection_name]['state']['balances'][user]}")
                return None, None, None, None, None
        
        return stack, memory, pc, cache_state, cache_accounts

    for id in cache_state[collection_name]:
        if id == 'state' or id == 'prev_states':
            continue
        
        tx = cache_state[collection_name][id]

        if i == 0:
            next_week = 1618866000
            next_month = 1620680400
    
        if collection_name == EVENTC[SELL]:
            # after a sale entry, increase values
            amount = tx['tray_no'] * tx['tray_price']
            cache_state[collection_name]['state']['total_earned'] += amount
            cache_state[collection_name]['state']['total_sales'] += 1
            cache_state[collection_name]['state']['total_trays_sold'] += tx['tray_no']
            section = 'section'

            cache_state[collection_name]['state'][f'total_earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += amount
            cache_state[collection_name]['state'][f'total_trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += tx['tray_no']

            # check if new week or new month
            if tx['date']['unix'] > next_week:
                # calculate change given last 2 complete weeks
                prev_week = next_week - week_in_seconds
                temp_next_week = next_week
    
                while str(prev_week) not in cache_state[collection_name]['state']['week_trays_sold_earned']:
                    if prev_week < 0:
                        if Decimal(next_week) != Decimal(1618866000):
                            log.error(f"No previous week found from {next_week}")
                            return None, None, None, None, None
                        
                        prev_week = next_week - week_in_seconds
                        cache_state[collection_name]['state']['week_trays_sold_earned'][str(prev_week)] = {}
                        log.warning(f"No previous week found from {prev_week}")
                        break
                    prev_week -= week_in_seconds
         
                while str(temp_next_week) not in cache_state[collection_name]['state']['week_trays_sold_earned']:
                    if temp_next_week < 0:
                        log.error(f"No next week found from {next_week}")
                        return None, None, None, None, None
                    temp_next_week -= week_in_seconds
          
                
                prev_week_dict = cache_state[collection_name]['state']['week_trays_sold_earned'][str(prev_week)]
                current_week_dict = cache_state[collection_name]['state']['week_trays_sold_earned'][str(temp_next_week)]

                def f(k, v):
                    return v - (prev_week_dict[k] if k in prev_week_dict else Decimal(0))

                week_val_diff = {k: f(k, v) for k, v in current_week_dict.items()}
                cache_state[collection_name]['state']['change_week'][f'{temp_next_week}'] = week_val_diff

                next_week += week_in_seconds

                cache_state[collection_name]['state']['week_trays_sold_earned'][str(next_week)] = {}
                week_dict = cache_state[collection_name]['state']['week_trays_sold_earned'][str(next_week)]

                week_dict['earned'] = amount
                week_dict[f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                week_dict['trays_sold'] = tx['tray_no']
                week_dict[f'trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['tray_no']

            else:
                if i == 0:
                    cache_state[collection_name]['state']['week_trays_sold_earned'][str(next_week)] = {}

                week_dict = cache_state[collection_name]['state']['week_trays_sold_earned'][str(next_week)]
                week_dict['earned'] = amount + week_dict['earned'] if 'earned' in week_dict else Decimal(0)
                week_dict['trays_sold'] = tx['tray_no'] + week_dict['trays_sold'] if 'trays_sold' in week_dict else Decimal(0)

                if f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}' in week_dict: 
                    week_dict[f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += amount
                    week_dict[f'trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += tx['tray_no']
                else:
                    week_dict[f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                    week_dict[f'trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['tray_no']

            # if new month
            if tx['date']['unix'] > next_month:
                # calculate change given last 2 complete months
                prev_month = next_month - month_in_seconds
                temp_next_month = next_month
    
                while str(prev_month) not in cache_state[collection_name]['state']['month_trays_sold_earned']:
                    if prev_month < 0:
                        if Decimal(next_month) != Decimal(1620680400):
                            log.error(f"No previous month found from {next_month}")
                            return None, None, None, None, None
                        
                        prev_month = next_month - month_in_seconds
                        cache_state[collection_name]['state']['month_trays_sold_earned'][str(prev_month)] = {}
                        log.warning(f"No previous month found from {prev_month}")
                        break
                    prev_month -= month_in_seconds
                
                while str(temp_next_month) not in cache_state[collection_name]['state']['month_trays_sold_earned']:
                    if temp_next_month < 0:
                        log.error(f"No next month found from {next_month}")
                        return None, None, None, None, None
                    temp_next_month -= month_in_seconds
                

                prev_month_dict = cache_state[collection_name]['state']['month_trays_sold_earned'][str(prev_month)]
                current_month_dict = cache_state[collection_name]['state']['month_trays_sold_earned'][str(temp_next_month)]

                def f(k, v):
                    return v - (prev_month_dict[k] if k in prev_month_dict else Decimal(0))

                month_val_diff = {k: f(k, v) for k, v in current_month_dict.items()}
                cache_state[collection_name]['state']['change_month'][f'{temp_next_month}'] = month_val_diff

                next_month += month_in_seconds

                cache_state[collection_name]['state']['month_trays_sold_earned'][str(next_month)] = {}
                month_dict = cache_state[collection_name]['state']['month_trays_sold_earned'][str(next_month)]

                month_dict['earned'] = amount
                month_dict[f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                month_dict['trays_sold'] = tx['tray_no']
                month_dict[f'trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['tray_no']
                
            else:
                if i == 0:
                    cache_state[collection_name]['state']['month_trays_sold_earned'][str(next_month)] = {}
                
                month_dict = cache_state[collection_name]['state']['month_trays_sold_earned'][str(next_month)]
                month_dict['earned'] = amount + month_dict['earned'] if 'earned' in month_dict else Decimal(0)
                month_dict['trays_sold'] = tx['tray_no'] + month_dict['trays_sold'] if 'trays_sold' in month_dict else Decimal(0)

                if f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}' in month_dict:
                    month_dict[f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += amount
                    month_dict[f'trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += tx['tray_no']
                else:
                    month_dict[f'earned_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                    month_dict[f'trays_sold_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['tray_no']

        elif collection_name == EVENTC[BUY]:
            # after a buy entry, increase values
            amount = tx['item_no'] * tx['item_price']
            cache_state[collection_name]['state']['total_spent'] += amount
            cache_state[collection_name]['state']['total_purchases'] += 1
            cache_state[collection_name]['state']['total_items_bought'] += tx['item_no']
            section = 'section'

            cache_state[collection_name]['state'][f'total_spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += amount
            cache_state[collection_name]['state'][f'total_items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += tx['item_no']

            # check if new week or new month
            if tx['date']['unix'] > next_week:
                # calculate change given last 2 complete weeks
                prev_week = next_week - week_in_seconds
                temp_next_week = next_week
               
                while str(prev_week) not in cache_state[collection_name]['state']['week_items_bought_spent']:
                    if prev_week < 0:
                        if Decimal(next_week) != Decimal(1618866000):
                            log.error(f"No previous week found from {next_week}")
                            return None, None, None, None, None

                        prev_week = next_week - week_in_seconds
                        cache_state[collection_name]['state']['week_items_bought_spent'][str(prev_week)] = {}
                        log.warning(f"No previous week found from {prev_week}")
                        break
                    prev_week -= week_in_seconds
                
                while str(temp_next_week) not in cache_state[collection_name]['state']['week_items_bought_spent']:
                    if temp_next_week < 0:
                        log.error(f"No next week found from {next_week}")
                        return None, None, None, None, None
                    temp_next_week -= week_in_seconds
                

                prev_week_dict = cache_state[collection_name]['state']['week_items_bought_spent'][str(prev_week)]
                current_week_dict = cache_state[collection_name]['state']['week_items_bought_spent'][str(temp_next_week)]

                def f(k, v):
                    return v - (prev_week_dict[k] if k in prev_week_dict else Decimal(0))

                week_val_diff = {k: f(k, v) for k, v in current_week_dict.items()}
                cache_state[collection_name]['state']['change_week'][f'{temp_next_week}'] = week_val_diff

                next_week += week_in_seconds

                cache_state[collection_name]['state']['week_items_bought_spent'][str(next_week)] = {}
                week_dict = cache_state[collection_name]['state']['week_items_bought_spent'][str(next_week)]

                week_dict['spent'] = amount
                week_dict[f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                week_dict['items_bought'] = tx['item_no']
                week_dict[f'items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['item_no']

            else:
                if i == 0:
                    cache_state[collection_name]['state']['week_items_bought_spent'][str(next_week)] = {}

                week_dict = cache_state[collection_name]['state']['week_items_bought_spent'][str(next_week)]
                week_dict['spent'] = amount + week_dict['spent'] if 'spent' in week_dict else Decimal(0)
                week_dict['items_bought'] = tx['item_no'] + week_dict['items_bought'] if 'items_bought' in week_dict else Decimal(0)

                if f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}' in week_dict:
                    week_dict[f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += amount
                    week_dict[f'items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += tx['item_no']
                else:
                    week_dict[f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                    week_dict[f'items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['item_no']
            
            # if new month
            if tx['date']['unix'] > next_month:
                # calculate change given last 2 complete months
                prev_month = next_month - month_in_seconds
                temp_next_month = next_month
                
                while str(prev_month) not in cache_state[collection_name]['state']['month_items_bought_spent']:
                    if prev_month < 0:
                        if Decimal(next_month) != Decimal(1620680400):
                            log.error(f"No previous month found from {next_month}")
                            return None, None, None, None, None
                        
                        prev_month = next_month - month_in_seconds
                        cache_state[collection_name]['state']['month_items_bought_spent'][str(prev_month)] = {}
                        log.warning(f"No previous month found from {prev_month}")
                        break
                    prev_month -= month_in_seconds
                
                while str(temp_next_month) not in cache_state[collection_name]['state']['month_items_bought_spent']:
                    if temp_next_month < 0:
                        log.error(f"No next month found from {next_month}")
                        return None, None, None, None, None
                    temp_next_month -= month_in_seconds
                

                prev_month_dict = cache_state[collection_name]['state']['month_items_bought_spent'][str(prev_month)] if str(prev_month) in cache_state[collection_name]['state']['month_items_bought_spent'] else {}
                current_month_dict = cache_state[collection_name]['state']['month_items_bought_spent'][str(temp_next_month)]

                def f(k, v):
                    return v - (prev_month_dict[k] if k in prev_month_dict else Decimal(0))

                month_val_diff = {k: f(k, v) for k, v in current_month_dict.items()}
                cache_state[collection_name]['state']['change_month'][f'{temp_next_month}'] = month_val_diff

                next_month += month_in_seconds

                cache_state[collection_name]['state']['month_items_bought_spent'][str(next_month)] = {}
                month_dict = cache_state[collection_name]['state']['month_items_bought_spent'][str(next_month)]

                month_dict['spent'] = amount
                month_dict[f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                month_dict['items_bought'] = tx['item_no']
                month_dict[f'items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['item_no']
                
            else:
                if i == 0:
                    cache_state[collection_name]['state']['month_items_bought_spent'][str(next_month)] = {}

                month_dict = cache_state[collection_name]['state']['month_items_bought_spent'][str(next_month)]
                month_dict['spent'] = amount + month_dict['spent'] if 'spent' in month_dict else Decimal(0)
                month_dict['items_bought'] = tx['item_no'] + month_dict['items_bought'] if 'items_bought' in month_dict else Decimal(0)

                if f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}' in month_dict:
                    month_dict[f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += amount
                    month_dict[f'items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] += tx['item_no']
                else:
                    month_dict[f'spent_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = amount
                    month_dict[f'items_bought_{tx[section].lower()[1:] if tx[section].lower()[1:] == other else tx[section].lower()}'] = tx['item_no']

        elif collection_name == EVENTC[EGGS]:
            # after an eggs entry, increase values
            amount = tx['a1'] + tx['a2'] + tx['b1'] + tx['b2'] + tx['c1'] + tx['c2'] + tx['house']
            state = cache_state[collection_name]['state']
            state['total_eggs'] += amount
            sections = ['a1','a2', 'b1', 'b2', 'c1', 'c2', 'broken', 'house']

            for sec in sections:
                state[f'total_eggs_{sec}'] += tx[sec]
            
            state['trays_collected_to_timestamp'][str(tx['date']['unix'])] = tx['trays_collected']
            state['diff_trays_to_exact'][str(tx['date']['unix'])] = get_eggs_diff(tx['trays_collected'], amount)[0]

            # check if new week or new month
            if tx['date']['unix'] > next_week:
                # calculate change given last 2 complete weeks
                prev_week = next_week - week_in_seconds
                temp_next_week = next_week

                while str(prev_week) not in cache_state[collection_name]['state']['week_trays_and_exact']:
                    if prev_week < 0:
                        if Decimal(next_week) != Decimal(1618866000):
                            log.error(f"No previous week found from {next_week}")
                            return None, None, None, None, None
                        
                        prev_week = next_week - week_in_seconds
                        cache_state[collection_name]['state']['week_trays_and_exact'][str(prev_week)] = {}
                        log.warning(f"No previous week found from {prev_week}")
                        break
                    prev_week -= week_in_seconds
                while str(temp_next_week) not in cache_state[collection_name]['state']['week_trays_and_exact']:
                    if temp_next_week < 0:
                        log.error(f"No next week found from {next_week}")
                        return None, None, None, None, None
                    temp_next_week -= week_in_seconds

                prev_week_dict = state['week_trays_and_exact'][str(prev_week)]
                current_week_dict = state['week_trays_and_exact'][str(temp_next_week)]

                def f(k, v):
                    return get_eggs_diff(v, (prev_week_dict[k] if k in prev_week_dict else Decimal(0)))[0]

                week_val_diff = {k: f(k, v) for k, v in current_week_dict.items()}
                state['change_week'][f'{temp_next_week}'] = week_val_diff

                next_week += week_in_seconds

                state['week_trays_and_exact'][str(next_week)] = {}
                week_dict = state['week_trays_and_exact'][str(next_week)]

                week_dict['trays_collected'] = tx['trays_collected']
                week_dict['exact'] = get_eggs(amount)[0]

            else:
                if i == 0:
                    state['week_trays_and_exact'][str(next_week)] = {}

                week_dict = state['week_trays_and_exact'][str(next_week)]
                week_dict['trays_collected'] = increment_eggs(tx['trays_collected'], week_dict['trays_collected'] if 'trays_collected' in week_dict else Decimal(0))[0]
                week_dict['exact'] = increment_eggs(amount, week_dict['exact'] if 'exact' in week_dict else Decimal(0))[0]

                if week_dict['trays_collected'] is None or week_dict['exact'] is None:
                    return None, None, None, None, None
            
            # if new month
            if tx['date']['unix'] > next_month:
                # calculate change given last 2 complete months
                prev_month = next_month - month_in_seconds
                temp_next_month = next_month
                while str(prev_month) not in cache_state[collection_name]['state']['month_trays_and_exact']:
                    if prev_month < 0:
                        if Decimal(next_month) != Decimal(1620680400):
                            log.error(f"No previous month found from {next_month}")
                            return None, None, None, None, None
                        
                        prev_month = next_month - month_in_seconds
                        cache_state[collection_name]['state']['month_trays_and_exact'][str(prev_month)] = {}
                        log.warning(f"No previous month found from {prev_month}")
                        break
                    prev_month -= month_in_seconds
                while str(temp_next_month) not in cache_state[collection_name]['state']['month_trays_and_exact']:
                    if temp_next_month < 0:
                        log.error(f"No next month found from {next_month}")
                        return None, None, None, None, None
                    temp_next_month -= month_in_seconds

                prev_month_dict = state['month_trays_and_exact'][str(prev_month)]
                current_month_dict = state['month_trays_and_exact'][str(temp_next_month)]

                def f(k, v):
                    return get_eggs_diff(v, (prev_month_dict[k] if k in prev_month_dict else Decimal(0)))[0]

                month_val_diff = {k: f(k, v) for k, v in current_month_dict.items()}
                state['change_month'][f'{temp_next_month}'] = month_val_diff

                next_month += month_in_seconds

                state['month_trays_and_exact'][str(next_month)] = {}
                month_dict = state['month_trays_and_exact'][str(next_month)]

                month_dict['trays_collected'] = tx['trays_collected']
                month_dict['exact'] = get_eggs(amount)[0]
                state['month_trays_and_exact'][str(next_month)] = month_dict

            else:
                if i == 0:
                    state['month_trays_and_exact'][str(next_month)] = {}

                month_dict = state['month_trays_and_exact'][str(next_month)]
                month_dict['trays_collected'] = increment_eggs(tx['trays_collected'], (month_dict['trays_collected'] if 'trays_collected' in month_dict else Decimal(0)))[0]
                month_dict['exact'] = increment_eggs(amount, (month_dict['exact'] if 'exact' in month_dict else Decimal(0)))[0]
                state['month_trays_and_exact'][str(next_month)] = month_dict
                
                if month_dict['trays_collected'] is None or month_dict['exact'] is None:
                    return None, None, None, None, None

            cache_state[collection_name]['state'] = state

        elif collection_name == EVENTC[DS]:
            if tx['section'] == 'DEAD':
                if 'total_dead' in cache_state[collection_name]['state']:
                    cache_state[collection_name]['state']['total_dead'] += Decimal(tx['number'])
                else:
                    cache_state[collection_name]['state']['total_dead'] = Decimal(tx['number'])
        

        i += 1

    return stack, memory, pc, cache_state, cache_accounts


def incr_balance(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: INCRBAL")
    pc += 1

    address = stack.pop()
    amount = stack.pop()
    cache_accounts[address] += amount

    log.info(f"New balance of {address}: {cache_accounts[address]}")

    return stack, memory, pc, cache_state, cache_accounts


def decr_balance(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DECRBAL")
    pc += 1

    address = stack.pop()
    amount = stack.pop()
    temp = cache_accounts[address] - amount
    if temp < Decimal(0):
        log.error(f"Balance decrement became negative addr: {address} from {cache_accounts[address]}, amount {amount}")
        return None, None, None, None, None
    
    cache_accounts[address] -= amount
    log.info(f"New balance of {address}: {cache_accounts[address]}")

    return stack, memory, pc, cache_state, cache_accounts


def get_dicts():
    return cache_deleted, cache_ui_txs, cache_dashboard_data, cache_verification_data


def calculate_root_hash(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CALCROOTHASH")
    pc += 1

    collection_name = stack.pop()
    sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1]['date']['unix'] if 'date' in item[1] and 'unix' in item[1]['date'] else Decimal(0))
    cache_state[collection_name] = {k: v for k, v in sorted_tuples}
    
    true_hashes = []
    
    for id in cache_state[collection_name]:
        tx_data_to_hash = ''
        if id == 'state' or id == 'prev_states':
            continue
        
        tx = cache_state[collection_name][id]
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
            
        log.debug(f"{collection_name} id: {id} tx data to hash, {tx_data_to_hash}")
        true_hashes.append(tx_data_to_hash)

    def internal_hash(to_hash):
        m = hashlib.sha256()
        m.update(to_hash.encode())
        return m.hexdigest()

    true_hashes = map(internal_hash, true_hashes)
    i = 0
    for id in cache_state[collection_name]:
        if id == 'state' or id == 'prev_states':
            continue
        cache_state[collection_name]['state']['all_tx_hashes'][id]['true_hash'] = true_hashes[i]
        i += 1
        
            
    stack.push(true_hashes)
    stack.push(Decimal(len(true_hashes)))
        
    return stack, memory, pc, cache_state, cache_accounts


def update_root_hash(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: UPROOTHASH")
    pc += 1

    hash = stack.pop()
    collection_name = stack.pop()
    if collection_name != 'main':
        cache_state[collection_name]['state']['root_hash'] = hash
        log.debug(f"New state: {cache_state[collection_name]['state']}")
        return stack, memory, pc, cache_state, cache_accounts
    else:
        cache_state['world_state']['main']['root'] = hash   
        log.debug(f"New main state: {cache_state['world_state']['main']}")
        return stack, memory, pc, cache_state, cache_accounts


# assumes all required fields are already populated
def calculate_main_state(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: CALCMAINSTATE")
    pc += 1

    net_profit = Decimal(cache_state['sales']['state']['total_earned']) - Decimal(cache_state['purchases']['state']['total_spent'])
    week_profit = {}
    month_profit = {}
    for k in cache_state['sales']['state']['week_trays_sold_earned']:
        spent = Decimal(0)
        if k in cache_state['purchases']['state']['week_items_bought_spent']:
            spent = cache_state['purchases']['state']['week_items_bought_spent'][k]['spent'] if 'spent' in cache_state['purchases']['state']['week_items_bought_spent'][k] else Decimal(0)
        else:
            log.warning(f"Nothing bought on week {k}")

        sold = cache_state['sales']['state']['week_trays_sold_earned'][k]['earned'] if 'earned' in cache_state['sales']['state']['week_trays_sold_earned'][k] else Decimal(0)
        net = Decimal(sold) - Decimal(spent)
        week_profit[k] = net
    
    for m in cache_state['purchases']['state']['week_items_bought_spent']:
        if m not in week_profit:
            spent = cache_state['purchases']['state']['week_items_bought_spent'][m]['spent'] if 'spent' in cache_state['purchases']['state']['week_items_bought_spent'][m] else Decimal(0)
            net = Decimal(0) - Decimal(spent)
            week_profit[m] = net
    
    for k in cache_state['sales']['state']['month_trays_sold_earned']:
        spent = Decimal(0)
        if k in cache_state['purchases']['state']['month_items_bought_spent']:
            spent = cache_state['purchases']['state']['month_items_bought_spent'][k]['spent'] if 'spent' in cache_state['purchases']['state']['month_items_bought_spent'][k] else Decimal(0)
        else:
            log.warning(f"Nothing bought on month {k}")
        
        sold = cache_state['sales']['state']['month_trays_sold_earned'][k]['earned'] if 'earned' in cache_state['sales']['state']['month_trays_sold_earned'][k] else Decimal(0)
        net = Decimal(sold) - Decimal(spent)
        month_profit[k] = net
    
    for m in cache_state['purchases']['state']['month_items_bought_spent']:
        if m not in month_profit:
            spent = cache_state['purchases']['state']['month_items_bought_spent'][m]['spent'] if 'spent' in cache_state['purchases']['state']['month_items_bought_spent'][m] else Decimal(0)
            net = Decimal(0) - Decimal(spent)
            month_profit[m] = net
    
    if net_profit > 0:
        # TODO add a check for any withdraws that have ever happened, subtract it from this
        profit_ratio = Decimal('0.15')
        cache_state['world_state']['main']['available_to_withdraw']['JEFF'] =  profit_ratio * net_profit 
        cache_state['world_state']['main']['available_to_withdraw']['VICTOR'] =  profit_ratio * net_profit 
        cache_state['world_state']['main']['available_to_withdraw']['BABRA'] =  profit_ratio * net_profit
        cache_state['world_state']['main']['available_to_withdraw']['REMAIN'] = net_profit - (profit_ratio * net_profit * Decimal(3))
    else:
        cache_state['world_state']['main']['available_to_withdraw']['JEFF'] =  Decimal(0)
        cache_state['world_state']['main']['available_to_withdraw']['VICTOR'] =  Decimal(0)
        cache_state['world_state']['main']['available_to_withdraw']['BABRA'] = Decimal(0)
        cache_state['world_state']['main']['available_to_withdraw']['REMAIN'] = Decimal(0)


    total_birds = starting_birds_no - cache_state['dead_sick']['state']['total_dead']
    world_state = cache_state['world_state']['main']
    total_birds = Decimal(total_birds)


    current_week = cache_state['eggs_collected']['state']['week_trays_and_exact'].keys()
    current_month = cache_state['eggs_collected']['state']['month_trays_and_exact'].keys()
    week_in_seconds = 7 * 24 * 60 * 60
    week_in_seconds = Decimal(week_in_seconds)
    month_in_seconds = 28 * 24 * 60 * 60
    month_in_seconds = Decimal(month_in_seconds)

    if current_week:
        current_week = Decimal(max(current_week))
        current_week -= week_in_seconds # we go back one week as we assume the current week can receive new data anytime, hence not complete
        temp = current_week

        while str(current_week) not in cache_state['eggs_collected']['state']['week_trays_and_exact']:
            if current_week < 0:
                log.error(f"No last week laying data found from {temp}")
                return None, None, None, None, None
            current_week -= week_in_seconds

        current_week = str(current_week)
    else:
        log.error("Current week does not exist in eggs_collected")
        return None, None, None, None, None
    
    if current_month:
        current_month = Decimal(max(current_month))
        current_month -= month_in_seconds # we go back one month as we assume the current month can receive new data anytime, hence not complete
        temp = current_month
        while str(current_month) not in cache_state['eggs_collected']['state']['month_trays_and_exact']:
            if current_month < 0:
                log.error(f"No last month laying data found from {temp}")
                return None, None, None, None, None
            current_month -= month_in_seconds

        current_month = str(current_month)
    else:
        log.error("Current month does not exist in eggs_collected")
        return None, None, None, None, None
    
    amount_eggs_week = cache_state['eggs_collected']['state']['week_trays_and_exact'][current_week]['trays_collected']
    amount_eggs_week = get_eggs(amount_eggs_week)[1]
    amount_eggs_month = cache_state['eggs_collected']['state']['month_trays_and_exact'][current_month]['trays_collected']
    amount_eggs_month = get_eggs(amount_eggs_month)[1]

    week_laying_percent = (amount_eggs_week / (Decimal(total_birds) * 7)) * Decimal(100)
    month_laying_percent = (amount_eggs_month / (Decimal(total_birds) * 28)) * Decimal(100)
    try:
        week_laying_percent = week_laying_percent.quantize(TWOPLACES)
    except InvalidOperation:
        log.error(f"Invalid Decimal Operation on weekly egg percent, value: {week_laying_percent}")
        return None, None, None, None, None

    try:
        month_laying_percent = month_laying_percent.quantize(TWOPLACES)
    except InvalidOperation:
        log.error(f"Invalid Decimal Operation on monthly egg percent, value: {month_laying_percent}")
        return None, None, None, None, None

    all_trays_sold = [Decimal(v['tray_no']) for k, v in cache_state['sales'].items() if k != 'state' and k != 'prev_states']
    all_trays_collected = [v['trays_collected'] for k, v in cache_state['eggs_collected'].items() if k != 'state' and k != 'prev_states']

    all_trays_sold = f'{reduce(lambda x, y: x+y, all_trays_sold, Decimal(0))},0'
    all_trays_collected = reduce(reduce_add_eggs, all_trays_collected, "0,0")
    
    cache_state['world_state']['main']['week_laying_percent'][current_week] = week_laying_percent
    cache_state['world_state']['main']['month_laying_percent'][current_month] = month_laying_percent
    cache_state['world_state']['main']['total_profit'] = net_profit
    cache_state['world_state']['main']['week_profit'] = week_profit
    cache_state['world_state']['main']['month_profit'] = month_profit
    cache_state['world_state']['main']['total_birds'] = total_birds
    cache_state['world_state']['main']['trays_available'] = get_eggs_diff(all_trays_collected, all_trays_sold)[0]

    to_hash_list = [cache_state['sales']['state']['root_hash'], cache_state['purchases']['state']['root_hash'], cache_state['eggs_collected']['state']['root_hash'], cache_state['dead_sick']['state']['root_hash'], cache_state['trades']['state']['root_hash']]
    stack.push(to_hash_list)
    stack.push(Decimal(len(to_hash_list)))

    return stack, memory, pc, cache_state, cache_accounts


def balance(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: BALANCE")
    pc += 1

    name = stack.pop()
    bal = cache_accounts.get(name, 0)
    stack.push(Decimal(f'{bal}'))
    return stack, memory, pc, cache_state, cache_accounts


# takes unix epoch and checks if enough trays existed for the sale to be valid
def is_sale_trays_safe(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: TRAYSAVAIL")
    pc += 1

    tray_no = stack.pop()
    unix_epoch = stack.pop()

    all_trays_sold = [Decimal(v['tray_no']) for k, v in cache_state['sales'].items() if k != 'state' and k != 'prev_states' and v['date']['unix'] <= unix_epoch]
    all_trays_collected = [v['trays_collected'] for k, v in cache_state['eggs_collected'].items() if k != 'state' and k != 'prev_states' and v['date']['unix'] <= unix_epoch]

    all_trays_sold = f'{reduce(lambda x, y: x+y, all_trays_sold, Decimal(0))},0'
    all_trays_collected = reduce(reduce_add_eggs, all_trays_collected, "0,0")
    remain = get_eggs_diff(all_trays_collected, all_trays_sold)[0]
    remain = get_eggs_diff(remain, f'{tray_no},0')[1]

    stack.push(Decimal(0) if remain >= Decimal(0) else Decimal(1))

    return stack, memory, pc, cache_state, cache_accounts


# get all dead txs with time less than or == given push laying percent
def laying_percent(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: LAYINGPERCENT")
    pc += 1

    unix_epoch = stack.pop()
    period = stack.pop()

    dead_docs = cache_state['dead_sick']
    vals = [ Decimal(value['number']) for key, value in dead_docs.items() if key != 'state' and key != 'prev_states' and dead_docs[key]['section'] == 'DEAD' and Decimal(str(dead_docs[key]['date']['unix'])) <= unix_epoch ]
    all_dead = reduce(lambda a, b: a + b, vals, 0)
    rem_birds = starting_birds_no - all_dead
    total_eggs = Decimal('NaN')
    percent = Decimal('NaN')

    if period == "WEEK":
        if str(unix_epoch) not in cache_state['eggs_collected']['state']['week_trays_and_exact']:
            log.error(f"Given week does not exist in eggs_collected {unix_epoch}")
            return None, None, None, None, None
        
        total_eggs = cache_state['eggs_collected']['state']['week_trays_and_exact'][str(unix_epoch)]['trays_collected']
        total_eggs = get_eggs(total_eggs)[1]
        percent = (total_eggs / (Decimal(rem_birds) * Decimal(7))) * Decimal(100)

        try:
            percent = percent.quantize(TWOPLACES)
        except InvalidOperation:
            log.error(f"Invalid Decimal Operation on weekly egg percent, value: {percent}")
            return None, None, None, None, None

    elif period == "MONTH":
        if str(unix_epoch) not in cache_state['eggs_collected']['state']['month_trays_and_exact']:
            log.error(f"Given month does not exist in eggs_collected {unix_epoch}")
            return None, None, None, None, None
        
        total_eggs = cache_state['eggs_collected']['state']['month_trays_and_exact'][str(unix_epoch)]['trays_collected']
        total_eggs = get_eggs(total_eggs)[1]
        percent = (total_eggs / (Decimal(rem_birds) * Decimal(28))) * Decimal(100)

        try:
            percent = percent.quantize(TWOPLACES)
        except InvalidOperation:
            log.error(f"Invalid Decimal Operation on monthly egg percent, value: {percent}")
            return None, None, None, None, None
  
    
    stack.push(percent)

    return stack, memory, pc, cache_state, cache_accounts


# only called after update cache
def update_ui_entries(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: UIENTRIES")
    pc += 1

    for col_name in EVENTC.values():
        type = ''
        match col_name:
            case 'sales':
                type = 'Sale'
            case 'purchases':
                type = 'Purchase'
            case 'trades':
                type = 'Trade'
            case 'dead_sick':
                type = 'Dead or Sick'
            case 'eggs_collected':
                type = 'Eggs Collected'
            case _:
                log.error(f"No match case found for {col_name}")
                return None, None, None, None, None

        for hash in cache_state[col_name]:
            if hash == 'state' or hash == 'prev_states':
                continue
            cache_ui_txs[hash] = {
                'date': cache_state[col_name][hash]['date']['unix'],
                'hash': hash,
                'status': Decimal(1),
                'submitted_on': cache_state[col_name][hash]['submitted_on']['unix'],
                'type': type
            }
    log.info(f"UI transactions updated")

    return stack, memory, pc, cache_state, cache_accounts


# only called after update cache
def update_verification_data(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: VERIFYCOL")
    pc += 1

    valid_hashes = []

    for col_name in EVENTC.values():
        if col_name == 'eggs_collected':
            cache_verification_data['trays'] = cache_state[col_name]['state']['trays_collected_to_timestamp']
        
        for hash in cache_state[col_name]:
            if hash == 'state' or hash == 'prev_states':
                continue
            valid_hashes.append(hash)

    cache_verification_data['hashes'] = valid_hashes
        
    log.info(f"Verification data updated")

    return stack, memory, pc, cache_state, cache_accounts


# only called after update cache
def update_dashboard_data(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: DASHBOARD")
    pc += 1

    # get last 2 weeks and month profit
    def get_last_2_profit(period):
        all = cache_state['world_state']['main'][f'{period}_profit'].keys()
        all = map(lambda x: int(x), all)
        all = sorted(all)
        latest = all[-1]
        prev = all[-2]
        return latest, prev

    week_profit = {
        str(get_last_2_profit('week')[0]): cache_state['world_state']['main']['week_profit'][str(get_last_2_profit('week')[0])],
        str(get_last_2_profit('week')[1]): cache_state['world_state']['main']['week_profit'][str(get_last_2_profit('week')[1])],
    }
    month_profit = {
        str(get_last_2_profit('month')[0]): cache_state['world_state']['main']['month_profit'][str(get_last_2_profit('month')[0])],
        str(get_last_2_profit('month')[1]): cache_state['world_state']['main']['month_profit'][str(get_last_2_profit('month')[1])],
    }
    total_birds = cache_state['world_state']['main']['total_birds']
    withdraw_amount = {
        'JEFF': cache_state['world_state']['main']['available_to_withdraw']['JEFF'],
        'VICTOR': cache_state['world_state']['main']['available_to_withdraw']['VICTOR'],
        'BABRA': cache_state['world_state']['main']['available_to_withdraw']['BABRA']
    }
    bank_balance = cache_state['trades']['state']['balances']['BANK']
    amount_owe = {
        'VICTOR': cache_state['trades']['state']['balances']['VICTOR'],
        'JEFF': cache_state['trades']['state']['balances']['JEFF'],
        'PURITY': cache_state['trades']['state']['balances']['PURITY'],
        'BABRA': cache_state['trades']['state']['balances']['BABRA']
    }

    def get_laying_change_percent(period):
        laying_keys = cache_state['world_state']['main'][f'{period}_laying_percent'].keys()
        laying_percent = cache_state['world_state']['main'][f'{period}_laying_percent'][max(laying_keys)]
        change = get_eggs(cache_state['eggs_collected']['state']['change_week'][max(laying_keys)]['trays_collected'])[1]
        in_seconds = 7 * 24 * 60 * 60
        if period == 'month':
            in_seconds = 28 * 24 * 60 * 60
        
        prev_val = int(max(laying_keys)) - in_seconds
        change_percent = (change / get_eggs(cache_state['eggs_collected']['state'][f'{period}_trays_and_exact'][str(prev_val)]['trays_collected'])[1]) * Decimal(100)
        return [change_percent, laying_percent]

    laying_data = {
        'week': get_laying_change_percent('week'),
        'month': get_laying_change_percent('month')
    }
    trays_avail = cache_state['world_state']['main']['trays_available']

    sorted_tuples = sorted(cache_state['trades'].items(), key=lambda item: item[1]['date']['unix'] if 'date' in item[1] and 'unix' in item[1]['date'] else Decimal(0))
    cache_state['trades'] = {k: v for k, v in sorted_tuples}
    last_trades = {}
    i = 0

    for x in cache_state['trades']:
        if x == 'state' or x == 'prev_states':
            continue
        last_trades[x] = cache_state['trades'][x]
        i += 1
        if i == 5:
            break

    cache_dashboard_data = {
        'week_profit': week_profit,
        'month_profit': month_profit,
        'birds': total_birds,
        'withdraw': withdraw_amount,
        'bank': bank_balance,
        'owe': amount_owe,
        'laying': laying_data,
        'trays_avail': trays_avail,
        'last_trades': last_trades 
    }

    log.info(f"Dashboard data updated")

    return stack, memory, pc, cache_state, cache_accounts


# check if a change happened remote
# get main root hash compare with local, if same exit, if not
# get all root hashes, compare with local, if same error, else
# get set difference of remote and local tx hashes, if remote contains new tx hash and the tx hash is not in deleted, rerun code
# if local contains new tx hash, check if remote deleted contains same tx hash, if so rerun code,
# else write (world_state, given collection state & entry itself)
def compare_with_remote_and_write(stack=None, memory=None, pc=None, analysed=None):
    log.debug(f"{pc}: WRITE")
    pc += 1

    ws_col_ref = db.collection('world_state')
    world_state_ref = col_ref.document('main')

    deleted_col_ref = db.collection('deleted')

    transaction = db.transaction()

    @firestore.transactional
    def update_in_transaction(transaction, world_state_ref):
        deleted_ref_docs = deleted_col_ref.stream(transaction=transaction)
        snapshot = world_state_ref.get(transaction=transaction)

        deleted_docs = {}
        for doc in deleted_ref_docs:
            deleted_docs[doc.id] = doc.to_dict()

        remote_ws_dict = snapshot.to_dict()
        remote_root = remote_ws_dict['root']
        remote_col_roots = remote_ws_dict['col_roots']
        local_col_roots = set()

        for k in cache_state:
            if 'state' in cache_state[k]:
                local_col_roots.add(cache_state[k]['state']['root_hash'])
        

        if remote_root == cache_state['world_state']['main']['root']:
            log.info("Remote and local main root hash match, no changes were made")
            return stack, memory, pc, cache_state, cache_accounts
        
        if set(remote_col_roots) == local_col_roots:
            log.error(f"Remote and local collection root hashes match when main root don't, {local_col_roots}")
            return None, None, None, None, None
        

        altered_collections = local_col_roots - remote_col_roots
        col_names = []
        for v in altered_collections:
            # a set of local collections that were edited
            temp_col_names = [x for x in cache_state if x != 'world_state' and cache_state[x]['state']['root_hash'] == v]
            print(temp_col_names)
            col_names.append(temp_col_names[0])

        for x in col_names:
            local_tx_hashes = set(cache_state['world_state']['main']['all_hashes'][x].keys())
            remote_tx_hashes = set(remote_ws_dict['all_hashes'][x].keys())

            is_in_remote = remote_tx_hashes - local_tx_hashes
            for k in is_in_remote:
                if k not in cache_deleted:
                    # new cloud entry
                    log.info("Change happened in remote, cloud create, rerun signal sent...")
                    return stack, memory, -2, cache_state, cache_accounts
            
            is_in_local = local_tx_hashes - remote_tx_hashes
            for k in is_in_local:
                if k in deleted_docs:
                    # new cloud delete 
                    log.info("Change happened in remote, cloud delete, rerun signal sent...")
                    return stack, memory, -2, cache_state, cache_accounts
            
            # if no new delete or create happened in cloud, then maybe prev values was updated
            local_true_hashes = set(cache_state['world_state']['main']['all_hashes'][x].values())
            remote_true_hashes = set(remote_ws_dict['all_hashes'][x].values())
            prev_val_change = remote_true_hashes - local_true_hashes

            if len(prev_val_change) != 0:
                log.info("Change happened in remote, prev value, rerun signal sent...")
                    return stack, memory, -2, cache_state, cache_accounts
        
        map_nested_dicts_modify(self.cache_state, lambda v: float(v) if isinstance(v, Decimal) else v)
        map_nested_dicts_modify(self.cache_deleted, lambda v: float(v) if isinstance(v, Decimal) else v)
        map_nested_dicts_modify(self.cache_accounts, lambda v: float(v) if isinstance(v, Decimal) else v)
        map_nested_dicts_modify(self.cache_ui_txs, lambda v: float(v) if isinstance(v, Decimal) else v)
        map_nested_dicts_modify(self.cache_verification_data, lambda v: float(v) if isinstance(v, Decimal) else v)
        map_nested_dicts_modify(self.cache_dashboard_data, lambda v: float(v) if isinstance(v, Decimal) else v)
        log.info("dicts sanitized")

        for col_name in col_names:
            col_ref = db.collection(col_name)
            i = 0
            log.info(f"committing {col_name} docs...")
            for id in :
                doc_ref = col_ref.document(id)
                batch.set(doc_ref, self.cache_state[col_name][id])
                batch.commit()
                i += 1
                log.info(f"committed entry {i} of {len(self.cache_state[col_name].keys())}")

        log.info(f"all collections committed, committing extra data")
        
        del_col_ref = db.collection('deleted')
        acc_col_ref = db.collection('accounts')
        tx_ui_col_ref = db.collection('tx_ui')
        ver_data_col_ref = db.collection('verification_data')
        dash_col_ref = db.collection('dashboard_data')

        for id in self.cache_deleted:
            doc_ref = del_col_ref.document(id)
            batch.set(doc_ref, self.cache_deleted[id])
        
        batch.commit()
        log.info("deleted docs committed")
        
        doc_ref = acc_col_ref.document('accounts')
        batch.set(doc_ref, self.cache_accounts)

        log.info("accounts committed")

        i = 0
        log.info(f"committing UI txs docs...")
        for id in self.cache_ui_txs:
            doc_ref = tx_ui_col_ref.document(id)
            batch.set(doc_ref, self.cache_ui_txs[id])
            batch.commit()
            i += 1
            log.info(f"committed entry {i} of {len(self.cache_ui_txs.keys())}")

        log.info("UI transactions committed")
        
        doc_ref = ver_data_col_ref.document('verification')
        batch.set(doc_ref, self.cache_verification_data)

        log.info("Verification data committed")
        
        for id in self.cache_dashboard_data:
            doc_ref = dash_col_ref.document(id)
            batch.set(doc_ref, self.cache_dashboard_data[id])

        batch.commit()
        log.info("Data written successfully")

        transaction.update(city_ref, {
            u'population': snapshot.get(u'population') + 1
        })

    update_in_transaction(transaction, city_ref)snippets.py
    

    return stack, memory, pc, cache_state, cache_accounts

# each week and month is represented by a timestamp
# month is current_timestamp+28days, week is current_timestamp+7days
def initialise():
    print("initialising...")
    all_collections = []
    for name in cache_state:
        if name == 'world_state':
            continue
        all_collections.append(name)
        collection_ref = db.collection(name)
        state = cache_state[name]['state']

        if name == 'eggs_collected':
            state['total_eggs'] = 0
            sections = ['a1','a2', 'b1', 'b2', 'c1', 'c2', 'broken', 'house']
            for sec in sections:
                state[f'total_eggs_{sec}'] = 0

            state['trays_collected_to_timestamp'] = {}
            state['diff_trays_to_exact'] = {} # 0 represents unix 0
            state['week_trays_and_exact'] = {'1618261200': {'trays_collected': '0,0', 'exact': '0,0'}} # 0 represents timestamp week 0
            state['month_trays_and_exact'] = {'1618261200': {'trays_collected': '0,0', 'exact': '0,0'}} # 0 represents month 0
            state['change_week'] = {'1618261200': {'change_trays_collected': 0, 'change_exact': 0 }} # 0 represents (week 0 - week 0), 1 will represent (week 1 - week 0)
            state['change_month'] = {'1618261200': {'change_trays_collected': 0, 'change_exact': 0 }} # 0 represents (month 0 - month 0), 1 will represent (month 1 - month 0)

        elif name == 'sales':
            state['total_sales'] = 0
            state['total_earned'] = 0
            state['total_trays_sold'] = 0
            sections = ['thikafarmers', 'other', 'cakes', 'duka']
            for sec in sections:
                state[f'total_earned_{sec}'] = 0
                state[f'total_trays_sold_{sec}'] = 0
            # everytime there is a new buyer, we will add a new field total_earned_other_buyer_name

            state['week_trays_sold_earned'] = {'1652734800': {
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
            state['month_trays_sold_earned'] = {'1656968400': {
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
            state['change_week'] = {'1652734800': {
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
            state['change_month'] = {'1656968400': {
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
                state[f'total_items_bought_{sec}'] = 0
            # everytime there is a new buyer, we will add a new field total_earned_other_buyer_name

            state['week_items_bought_spent'] = {'1652734800': {
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
            state['month_items_bought_spent'] = {'1656968400': {
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
            state['change_week'] = {'1652734800': {
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
            state['change_month'] = {'1656968400': {
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
            def f(v):
                return float(v)
            state['balances'] = {k: f(v) for k, v in cache_accounts.items()}


        collection_ref.document('state').set(state)
        collection_ref.document('prev_states').set({'0': state })
        print(name, "added state")
    
    global_state_ref = db.collection('world_state')
    world_state = {
        'week_laying_percent': {'1618261200': {}},
        'month_laying_percent': {'1618261200': {}},
        'week_profit': {'0': 0 },
        'month_profit': {'0': 0 },
        'total_profit': 0,
        'available_to_withdraw': {'VICTOR': 0, 'BABRA': 0, 'JEFF': 0},
        'age_of_birds': {'start_date': {'unix': 0, 'locale': ''}, 'age': {'unix': 0, 'years': 0, 'months': 0, 'weeks': 0 }},
        'total_birds': 1, # divide by zero error
        'root': ''
    }
    
    global_state_ref.document('main').set(world_state)
    collection_ref.document('prev_states').set({'0': state })

#initialise()

inst_mapping = {
    str(Opcodes.PUSH.value): push,
    str(Opcodes.POP.value): pop,
    str(Opcodes.DUP.value): dup,
    str(Opcodes.ADD.value): add,
    str(Opcodes.MUL.value): mul,
    str(Opcodes.SUB.value): sub,
    str(Opcodes.DIV.value): div,
    str(Opcodes.EQ.value): eq,
    str(Opcodes.LT.value): lt,
    str(Opcodes.GT.value): gt,
    str(Opcodes.JUMPIF.value): jumpif,
    str(Opcodes.JUMPDEST.value): jumpdes,
    str(Opcodes.PANIC.value): panic,
    str(Opcodes.SWAP.value): swap,
    str(Opcodes.ISZERO.value): is_zero,
    str(Opcodes.STOP.value): stop,
    str(Opcodes.BALANCE.value): balance,
    str(Opcodes.ROOTHASH.value): root_hash,
    str(Opcodes.SHA256.value): sha256,
    str(Opcodes.UPDATECACHE.value): update_cache,
    str(Opcodes.WRITE.value): compare_with_remote_and_write,
    str(Opcodes.VERIFYCOL.value): update_verification_data,
    str(Opcodes.UIENTRIES.value): update_ui_entries,
    str(Opcodes.DASHBOARD.value): update_dashboard_data,
    str(Opcodes.STATE.value): get_state,
    str(Opcodes.LAYINGPERCENT.value): laying_percent,
    str(Opcodes.TRAYSAVAIL.value): is_sale_trays_safe,
    str(Opcodes.CENTRY.value): create_entry,
    str(Opcodes.CADDR.value): create_address,
    str(Opcodes.DADDR.value): delete_address,
    str(Opcodes.DECRBAL.value): decr_balance,
    str(Opcodes.INCRBAL.value): incr_balance,
    str(Opcodes.DENTRY.value): delete_entry,
    str(Opcodes.NOW.value): timestamp_now,
    str(Opcodes.CALCSTATE.value): full_calculate_new_state,
    str(Opcodes.MLOAD.value): mload,
    str(Opcodes.MSTORE.value): mstore,
    str(Opcodes.CALCROOTHASH.value): calculate_root_hash,
    str(Opcodes.UPROOTHASH.value): update_root_hash,
    str(Opcodes.CALCMAINSTATE.value): calculate_main_state
}
