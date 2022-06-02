# Instructions
from functools import reduce
from decimal import *
from firebase_admin import credentials
from firebase_admin import firestore

from opcodes import *
from util import get_collection_hashes
from log_ import log

import time
import hashlib
import firebase_admin

getcontext().traps[FloatOperation] = True
TWOPLACES = Decimal(10) ** -2 

cred = credentials.Certificate("core101-3afde-firebase-adminsdk-sxm20-194a475b51.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

CREATE = 'CREATE'
DELETE = 'DELETE'

cache_state = { 
    'sales': {},
    'purchases': {},
    'eggs_collected': {},
    'dead_sick': {},
    'trades': {}
}
cache_accounts = {}
instructions_executed = {}
new_entry_counter = -1              # keeps track of how many new entries we have


def push(elem=None, stack=None, memory=None, pc=None, analysed=None):
    pc += 2
    instructions_executed[str(pc)] = PUSH

    if isinstance(elem, float) or isinstance(elem, int):
        elem = Decimal(elem)

    if isinstance(elem, Decimal) or isinstance(elem, str):
        stack.push(elem)
        return stack, memory, pc, cache_state, cache_accounts
    else:
        log.error(f"Attempted to push not a str or a decimal type, {type(elem)}")
        return None, None, None, None, None


def add(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = ADD

    a = stack.pop()
    b = stack.pop()
    stack.push(b + a)
    
    return stack, memory, pc, cache_state, cache_accounts


def sub(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = SUB

    a = stack.pop()
    b = stack.pop()
    stack.push(b - a)
    return stack, memory, pc, cache_state, cache_accounts


def mul(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = MUL

    a = stack.pop()
    b = stack.pop()
    stack.push(b * a)
    return stack, memory, pc, cache_state, cache_accounts


def div(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = DIV

    a = stack.pop()
    b = stack.pop()
    stack.push(b / a)
    
    return stack, memory, pc, cache_state, cache_accounts


def dup(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = DUP

    num = stack.pop()
    arr = []

    for i in range(int(num)):
        arr.append(stack.pop())

    arr.reverse() # preserve LIFO
    stack.push(arr)
    stack.push(arr)

    return stack, memory, pc, cache_state, cache_accounts


def stop(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = STOP

    if stack.size() == 1:
        empty_state = { 
            'sales': {},
            'purchases': {},
            'eggs_collected': {},
            'dead_sick': {},
            'trades': {}
        }
        empty_accounts = {}
        if empty_accounts == cache_accounts and empty_state == cache_state:
            # successful exit
            val = stack.pop()
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
    pc += 1
    instructions_executed[str(pc)] = ROOTHASH

    collection_name = stack.pop()

    stack.push(cache_state[collection_name]['state']['root_hash'])
    return stack, memory, pc, cache_state, cache_accounts


def sha512(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = SHA512

    m = hashlib.sha512()
    num_of_elements = stack.pop()
    to_hash = ''

    for i in range(int(num_of_elements)):
        val = stack.pop()
        to_hash += str(val)
    
    log.debug(f"all hashes: {to_hash}")
    m.update(to_hash.encode())
    stack.push(m.hexdigest())

    return stack, memory, pc, cache_state, cache_accounts


# pushes tx hash to stack given collection and id
def tx_hash(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = TXHASH

    id = stack.pop()
    collection_name = stack.pop()

    stack.push(cache_state[collection_name][id]['tx_hash'])

    return stack, memory, pc, cache_state, cache_accounts


def is_zero(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = ISZERO

    val = stack.pop()

    stack.push(Decimal(1) if val == Decimal(0) else Decimal(0))

    return stack, memory, pc, cache_state, cache_accounts


def eq(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = EQ

    a = stack.pop()
    b = stack.pop()

    stack.push(Decimal(1) if a == b else Decimal(0))
    return stack, memory, pc, cache_state, cache_accounts


# followed by sha512
def collection_hashes_to_hash(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = COLLHASH

    collection_name = stack.pop()

    cache_hashes = get_collection_hashes(collection_name, cache_state)
    cache_hashes.reverse()

    stack.push(cache_hashes)
    stack.push(len(cache_hashes))
    return stack, memory, pc, cache_state, cache_accounts


# followed by sha512
def tx_values_to_hash(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = TXVALSHASH

    tx_hash_ = stack.pop()
    collection_name = stack.pop()

    values_to_hash = get_tx_data_to_hash(name=collection_name, cache_state=cache_state, tx_hash_=tx_hash_)
    values_to_hash.reverse()

    stack.push(values_to_hash)
    stack.push(len(values_to_hash))

    return stack, memory, pc, cache_state, cache_accounts


def get_state(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = UPDATESTATE

    collection_name = stack.pop()
    collection_ref = db.collection(collection_name)
    state_dict = collection_ref.document('state').get().to_dict()

    if not cache_state[collection_name]:
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
    pc += 1
    instructions_executed[str(pc)] = UPDATECACHE

    collection_name = stack.pop()

    collection_ref = db.collection(collection_name)
    state_dict = collection_ref.document('state').get().to_dict()
    
    if not cache_state[collection_name]:
        # no cache exists, proceed with query
        log.info("no cache exists, querying...")
        query = collection_ref.order_by('submitted_on', direction=firestore.Query.ASCENDING)
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
                    cache_state[collection_name]['temp_'+oldest['id']] = {
                        'tx_hash': oldest['tx_hash'],
                        'submitted_on': oldest['submitted_on']
                    }

                    local_oldest = oldest
                    update_attempted = 1                    
                elif operation_done == DELETE:
                    if cache_state[collection_name].get('temp_'+oldest['id'], False):
                        del cache_state[collection_name]['temp_'+oldest['id']]
                    else:
                        del cache_state[collection_name][oldest['id']]

                    local_oldest = oldest
                    update_attempted = 1

            if second['tx_hash'] != local_second.get('tx_hash', False):
                operation_done = second['op'] # can be delete or create

                if operation_done == CREATE:
                    cache_state[collection_name]['temp_'+second['id']] =  {
                        'tx_hash': oldest['tx_hash'],
                        'submitted_on': second['submitted_on']
                    }

                    local_second = second
                    update_attempted = 1
                
                elif operation_done == DELETE:
                    if cache_state[collection_name].get('temp_'+second['id'], False):
                        del cache_state[collection_name]['temp_'+second['id']]
                    else:
                        del cache_state[collection_name][second['id']]

                    local_second = second
                    update_attempted = 1
        
            if newest['tx_hash'] != local_newest.get('tx_hash', False):
                operation_done = newest['op'] # can be delete or create

                if operation_done == CREATE:
                    cache_state[collection_name]['temp_'+newest['id']] =  {
                        'tx_hash': oldest['tx_hash'],
                        'submitted_on': newest['submitted_on']
                    }
                    local_newest = newest
                    update_attempted = 1

                elif operation_done == DELETE:
                    if cache_state[collection_name].get('temp_'+newest['id'], False):
                        del cache_state[collection_name]['temp_'+newest['id']]
                    else:
                        del cache_state[collection_name][newest['id']]
                    local_newest = newest
                    update_attempted = 1
            

            if update_attempted:
                # since we inserted new elements, sort the dict so as to calculate correct hash
                sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1].get('submitted_on', 0))
                cache_state[collection_name] = {k: v for k, v in sorted_tuples}

                # push all hashes to stack
                cache_hashes = get_collection_hashes(collection_name, cache_state)

                # obey stack law of LIFO(Last in First Out)
                cache_hashes.reverse()

                stack.push(cache_hashes)
                stack.push(len(cache_hashes))

                return stack, memory, pc, cache_state, cache_accounts

            else:
                # final attempt at preventing a full query, get an array of all ids, perform set difference
                # of local and remote. Time complexity should be O(1) since python uses hash tables for sets

                update_attempted = 0

                remote_ids = set(state_dict['all_ids'].keys())
                local_ids = set(cache_state[collection_name].keys())

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
                        cache_state[collection_name][val] = {
                            'tx_hash': state_dict['all_ids'][val]['tx_hash'],
                            'submitted_on': state_dict['all_ids'][val]['submitted_on']
                        }
                        update_attempted = 1
                
                if update_attempted:
                    # since we inserted new elements, sort the dict so as to calculate correct hash
                    sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1].get('submitted_on', 0))
                    cache_state[collection_name] = {k: v for k, v in sorted_tuples}

                    # push all hashes to stack
                    cache_hashes = get_collection_hashes(collection_name, cache_state)

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


# TODO: replace 1634774400000.0 with time.time_ns()
def timestamp_now(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = NOW

    stack.push(Decimal('1.6530634936213117e+18'))
    return stack, memory, pc, cache_state, cache_accounts


def swap(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = SWAP

    a = stack.pop()
    b = stack.pop()
    stack.push(a)
    stack.push(b)
    return stack, memory, pc, cache_state, cache_accounts


def create_address(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = CADDR

    address_name = stack.pop()
    amount = stack.pop()
    cache_accounts[address_name] = amount
    return stack, memory, pc, cache_state, cache_accounts


def delete_address(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = DADDR

    address_name = stack.pop()
    del cache_accounts[address_name]
    return stack, memory, pc, cache_state, cache_accounts


def create_entry(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = CENTRY

    entry_name = stack.pop()
    new_entry_counter += 1

    if entry_name == 'SELL':
        cache_state['sales'][f'new{new_entry_counter}'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'tray_no', 'tray_price', 'buyer', 'date', 'section' ]
        for id in order:
            val = stack.pop()
            cache_state['sales'][f'new{new_entry_counter}'][id] = val


    elif entry_name == 'BUY':
        cache_state['purchases'][f'new{new_entry_counter}'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'item_no', 'item_price', 'item_name', 'date', 'section' ]
        for id in order:
            val = stack.pop()
            cache_state['purchases'][f'new{new_entry_counter}'][id] = val
    

    elif entry_name == 'DS':
        cache_state['dead_sick'][f'new{new_entry_counter}'] = {}
        order = [ 'submitted_on', 'by', 'image_url', 'image_id', 'reason', 'tx_hash', 'number', 'date', 'section', 'location']
        for id in order:
            val = stack.pop()
            cache_state['dead_sick'][f'new{new_entry_counter}'][id] = val

        
    elif entry_name == 'EGGS':
        cache_state['eggs_collected'][f'new{new_entry_counter}'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'tray_no', 'tray_price', 'buyer', 'date', 'section' ]
        for id in order:
            val = stack.pop()
            cache_state['eggs_collected'][f'new{new_entry_counter}'][id] = val
        
        log.debug(f'{cache_state}')

    elif entry_name == 'TRADE':
        cache_state['trades'][f'new{new_entry_counter}'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'tray_no', 'tray_price', 'buyer', 'date', 'section' ]
        for id in order:
            val = stack.pop()
            cache_state['trades'][f'new{new_entry_counter}'][id] = val
    
    else:
        log.error("Invalid entry")
        return None, None, None, None, None
    
    return stack, memory, pc, cache_state, cache_accounts


def delete_entry(stack=None, memory=None, pc=None, analysed=None):
    pc += 1
    instructions_executed[str(pc)] = DENTRY

    entry_id = stack.pop()
    collection_name = stack.pop()

    del cache_state[collection_name][entry_id]

    return stack, memory, pc, cache_state, cache_accounts


def prep_finalise_data(stack=None, memory=None, pc=None, analysed=None):
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

    instructions_executed[str(pc)] = PREPFINALISE
    return stack, memory, pc, cache_state, cache_accounts


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
    str(TXHASH): tx_hash,
    str(TXVALSHASH): tx_values_to_hash,
    str(COLLHASH): collection_hashes_to_hash,
    str(ROOTHASH): root_hash,
    str(SHA512): sha512,
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
SHA512 // tx_hash
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
SHA512 // tx_hash
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
SHA512 // tx_hash
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
SHA512 // tx_hash
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
SHA512 // tx_hash
PUSH r // reason
PUSH i // image_id
PUSH u // image_url
PUSH f // by
NOW    // submitted_on
PUSH EVENT
CENTRY





{after all create/delete operations execute this instructions}
PREPFINALISE
SHA512
TXHASH
EQ
EXITLOOP
JUMPIF
SHA512
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
