# Instructions
from opcodes import *
from util import get_collection_hashes
from functools import reduce
import time
import hashlib

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore


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
last_jump = -1                                  # keep track of last location before jump so as to go back once jump is called again
last_jump_2 = -1
last_instr = ''                                 # last instruction before a jump
jump_dest = -1
jump_dest_2 = -1

new_entry_counter = 0


def dup(stack, pc=None, analysed=None):
    num = stack.pop()
    arr = []

    for i in range(int(num)):
        arr.append(stack.pop())

    arr.reverse() # preserve LIFO
    # print("values dup:", arr)
    stack.push(arr)
    stack.push(arr)
    pc += 1
    instructions_executed[str(pc)] = DUP
    return stack, pc, cache_state, cache_accounts


def push(stack, elem, pc=None, analysed=None) :
    if isinstance(elem, float) or isinstance(elem, str):
        stack.push(elem)
        pc += 1
        instructions_executed[str(pc)] = PUSH
        return stack, pc, cache_state, cache_accounts
    else:
        print("Attempted to push non str or float")
        return None, None, None, None


def add(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b + a)
    pc += 1
    instructions_executed[str(pc)] = ADD
    return stack, pc, cache_state, cache_accounts


def sub(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b - a)
    pc += 1
    instructions_executed[str(pc)] = SUB
    return stack, pc, cache_state, cache_accounts


def mul(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b * a)
    pc += 1
    instructions_executed[str(pc)] = MUL
    return stack, pc, cache_state, cache_accounts


def div(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b / a)
    pc += 1
    instructions_executed[str(pc)] = DIV
    return stack, pc, cache_state, cache_accounts


def stop(stack, pc=None, analysed=None):
    if stack.size():
        print("Stack still contains:", stack.get_stack())
        return None, None, None, None

    # successful exit
    return stack, -1, cache_state, cache_accounts



# pushes root hash of a collection to stack
def root_hash(stack, pc=None, analysed=None) :
    collection_name = stack.pop()

    stack.push(cache_state[collection_name]['state']['root_hash'])
    pc += 1
    instructions_executed[str(pc)] = ROOTHASH
    return stack, pc, cache_state, cache_accounts


def jump_if(stack, pc=None, analysed=None) :
    cond = stack.pop()

    if cond:
        if last_jump != -1:
            pc = last_jump
            instructions_executed[str(pc)] = JUMPIF
            return stack, pc, cache_state, cache_accounts
        
        if last_jump_2 != -1:
            pc = last_jump_2
            instructions_executed[str(pc)] = JUMPIF
            return stack, pc, cache_state, cache_accounts

        if CONFIRMCACHE == last_instr:
            last_instr = ''
            print("root hash doesn't match even after full update")
            return None, None, None, None
        
        dest = stack.pop() # program counter number
        pc = dest
        instructions_executed[str(pc)] = JUMPIF
        return stack, pc, cache_state, cache_accounts
    else:
        if last_jump != -1:
            pc = last_jump
            last_jump = -1
            instructions_executed[str(pc)] = JUMPIF
            return stack, pc, cache_state, cache_accounts
        
        pc += 1
        instructions_executed[str(pc)] = JUMPIF
        return stack, pc, cache_state, cache_accounts


def sha512(stack, pc=None, analysed=None) :
    m = hashlib.sha512()

    num_of_elements = stack.pop()

    if not num_of_elements:
        # num_elements will NEVER be 0, hence this if statement acts as a signal received
        # to break from an infinite loop
        if jump_dest != -1:
            pc = jump_dest
            last_jump = -1
            jump_dest = -1
        elif jump_dest_2 != -1:
            pc = jump_dest_2
            last_jump_2 = -1
            jump_dest_2 = -1
        else:
            print("Errored jump instruction")
            return None, None, None, None
        
        instructions_executed[str(pc)] = 'signaled_exit_loop'
        return stack, pc, cache_state, cache_accounts


    to_hash = ''

    for i in range(int(num_of_elements)):
        val = stack.pop()
        to_hash += str(val)
    
    #print("all hashes:", to_hash)
    m.update(to_hash.encode())
    stack.push(m.hexdigest())

    pc += 1
    instructions_executed[str(pc)] = SHA512
    return stack, pc, cache_state, cache_accounts


# pushes tx hash to stack given collection and id
def tx_hash(stack, pc=None, analysed=None):
    calculated_hash = stack.pop()
    id = stack.pop()
    name = stack.pop()

    stack.push(cache_state[name][id]['tx_hash'])
    stack.push(calculated_hash)


def is_zero(stack, pc=None, analysed=None) :
    val = stack.pop()

    stack.push(1 if val == 0 else 0)
    pc += 1
    instructions_executed[str(pc)] = ISZERO
    return stack, pc, cache_state, cache_accounts


def eq(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()

    stack.push(1 if a == b else 0)
    pc += 1
    instructions_executed[str(pc)] = EQ
    return stack, pc, cache_state, cache_accounts


# followed by jumpif, always after an update_cache
def confirm_cache(stack, pc=None, analysed=None):
    collection_name = stack.pop()

    cache_hashes = get_collection_hashes(collection_name, cache_state)
    cache_hashes.reverse()

    pc += 1

    stack.push(collection_name)
    stack.push(cache_hashes)
    stack.push(len(cache_hashes))

    # we know that the next instruction will be a jumpif
    stack.push(analysed['VALID_JUMPDEST'][pc+1])
    last_jump = pc+2
    last_instr = CONFIRMCACHE

    stack.push(1)
    instructions_executed[str(pc)] = CONFIRMCACHE
    return stack, pc, cache_state, cache_accounts


# followed by a jumpif
def get_state(stack, pc=None, analysed=None):
    collection_name = stack.pop()
    collection_ref = db.collection(collection_name)
    state_dict = collection_ref.document('state').get().to_dict()

    if not cache_state[collection_name]:
        print("no state cache exists, adding...")
        cache_state[collection_name]['state'] = state_dict

        pc += 1
        stack.push(0)
        instructions_executed[str(pc)] = UPDATESTATE
        return stack, pc, cache_state, cache_accounts
    else:
        local_hash = cache_state[collection_name]['state']['root_hash']
        if local_hash == state_dict['root_hash']:
            pc += 1
            stack.push(0)
            instructions_executed[str(pc)] = UPDATESTATE
            return stack, pc, cache_state, cache_accounts
        
        pc += 1
        cache_state[collection_name] = {}
        stack.push(collection_name)
        stack.push(analysed['VALID_JUMPDEST'][pc+1]) # this location will have updatecache opcode
        stack.push(1)
        instructions_executed[str(pc)] = UPDATESTATE
        return stack, pc, cache_state, cache_accounts


# only called when comparing 2 hashes if don't match exit None
def exit_loop(stack, pc=None, analysed=None):
    a = stack.peek()
    if not a:
        print("Hashes don't match loop exited")
        return None, None, None, None
    else:
        pc += 1
    
    return stack, pc, cache_state, cache_accounts
    

# attempts to update the cache with latest values. Note that we will only need
# to call this function if we do create/delete operations, or plainly just need to confirm state. Most operations i.e.
# checking if a document exists require just the state document
# followed by a jumpif
def update_cache(stack, pc=None, analysed=None) :
    collection_name = stack.pop()

    collection_ref = db.collection(collection_name)
    state_dict = collection_ref.document('state').get().to_dict()
    
    if not cache_state[collection_name]:
        # no cache exists, proceed with query
        print("no cache exists")
        query = collection_ref.order_by('submitted_on', direction=firestore.Query.ASCENDING)
        results = query.stream()
        cache_state[collection_name]['state'] = state_dict
        for doc in results:
            cache_state[collection_name][doc.id] = doc.to_dict()
        
        pc += 1
        stack.push(collection_name)
        stack.push(0)
        instructions_executed[str(pc)] = UPDATECACHE
        return stack, pc, cache_state, cache_accounts
    
    else:
        print("cache exists confirming validity...")
        # check if state hashes match
        root_hash = state_dict['root_hash']
        local_hash = cache_state[collection_name]['state']['root_hash']
        
        if local_hash == root_hash:
            print("hashes match no need for update")
            pc += 1
            stack.push(collection_name)
            stack.push(0)
            instructions_executed[str(pc)] = UPDATECACHE
            return stack, pc, cache_state, cache_accounts
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
                    cache_state[collection_name][oldest['id']] = {
                        'tx_hash': oldest['tx_hash'],
                        'submitted_on': oldest['submitted_on']
                    }

                    local_oldest = oldest
                    update_attempted = 1
                    
                elif operation_done == DELETE:
                    del cache_state[collection_name][oldest['id']]
                    local_oldest = oldest
                    update_attempted = 1

            if second['tx_hash'] != local_second.get('tx_hash', False):
                operation_done = second['op'] # can be delete or create
                if operation_done == CREATE:
                    cache_state[collection_name][second['id']] =  {
                        'tx_hash': second['tx_hash'],
                        'submitted_on': second['submitted_on']
                    }

                    local_second = second
                    update_attempted = 1
                
                elif operation_done == DELETE:
                    del cache_state[collection_name][second['id']]
                    local_second = second
                    update_attempted = 1
        
            if newest['tx_hash'] != local_newest.get('tx_hash', False):
                operation_done = newest['op'] # can be delete or create
                if operation_done == CREATE:
                    cache_state[collection_name][newest['id']] =  {
                        'tx_hash': newest['tx_hash'],
                        'submitted_on': newest['submitted_on']
                    }
                    local_newest = newest
                    update_attempted = 1

                elif operation_done == DELETE:
                    del cache_state[collection_name][newest['id']]
                    local_newest = newest
                    update_attempted = 1
            

            if update_attempted:
                # since we inserted new elements, sort the dict so as to calculate correct hash
                sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1].get('submitted_on', 0))
                cache_state[collection_name] = {k: v for k, v in sorted_tuples}

                # push all hashes to stack
                cache_hashes = get_collection_hashes(collection_name, cache_state)

                # this is to obey the stack law of LIFO(Last in First Out)
                cache_hashes.reverse()

                pc += 1

                # jump destination incase we want to rexecute this function
                stack.push(pc)

                stack.push(collection_name)
                stack.push(cache_hashes)
                stack.push(len(cache_hashes))

                # to make code easier to follow, each jump if has a jump dest
                stack.push(analysed['VALID_JUMPDEST'][pc+1])

                stack.push(1)
                instructions_executed[str(pc)] = UPDATECACHE
                return stack, pc, cache_state, cache_accounts

            else:
                # final attempt at preventing a full query, get an array of all ids, perform set difference
                # of local and remote. Time complexity should be O(1) since python uses hash tables for sets

                update_attempted = 0

                remote_ids = set(state_dict['all_ids'].keys())
                local_ids = set(cache_state['sales'].keys())

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

                    pc += 1

                    # jump destination incase we want to rexecute this function
                    stack.push(pc)

                    stack.push(collection_name)
                    stack.push(cache_hashes)
                    stack.push(len(cache_hashes))

                    # to make code easier to follow, each jump if has a jump dest
                    stack.push(analysed['VALID_JUMPDEST'][pc+1])

                    stack.push(1)
                    instructions_executed[str(pc)] = UPDATECACHE
                    return stack, pc, cache_state, cache_accounts

                else:
                    # at this point, query all entries
                    print("state changes many, doing full update...")
                    query = collection_ref.order_by('submitted_on', direction=firestore.Query.ASCENDING)
                    results = query.stream()
                    cache_state[collection_name] = {}
                    cache_state[collection_name]['state'] = state_dict
                    for doc in results:
                        cache_state[collection_name][doc.id] = doc.to_dict()
                    

                    local_hash = cache_state[collection_name]['state']['root_hash']
                    pc += 1
                    stack.push(collection_name)
                    stack.push(0)
                    instructions_executed[str(pc)] = UPDATECACHE


# TODO: replace 1634774400000.0 with time.time_ns()
def timestamp_now(stack, pc=None, analysed=None):
    stack.push(float(1.6530634936213117e+18))
    pc += 1
    instructions_executed[str(pc)] = NOW
    return stack, pc, cache_state, cache_accounts



def swap(stack, pc=None, analysed=None):
    a = stack.pop()
    b = stack.pop()
    stack.push(a)
    stack.push(b)
    pc += 1
    instructions_executed[str(pc)] = SWAP
    return stack, pc, cache_state, cache_accounts


def create_address(stack, pc=None, analysed=None):
    address_name = stack.pop()
    amount = stack.pop()
    cache_accounts[address_name] = amount
    pc += 1
    instructions_executed[str(pc)] = CADDR
    return stack, pc, cache_state, cache_accounts


def delete_address(stack, pc=None, analysed=None):
    address_name = stack.pop()
    del cache_accounts[address_name]
    pc += 1
    instructions_executed[str(pc)] = DADDR
    return stack, pc, cache_state, cache_accounts


def create_entry(stack, pc=None, analysed=None):
    entry_name = stack.pop()

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
        
        #print(cache_state)

    elif entry_name == 'TRADE':
        cache_state['trades'][f'new{new_entry_counter}'] = {}
        order = [ 'submitted_on', 'by', 'tx_hash', 'tray_no', 'tray_price', 'buyer', 'date', 'section' ]
        for id in order:
            val = stack.pop()
            cache_state['trades'][f'new{new_entry_counter}'][id] = val
    
    else:
        print("Invalid entry")
        return None, None, None, None
    
    pc += 1
    instructions_executed[str(pc)] = CENTRY
    return stack, pc, cache_state, cache_accounts


def delete_entry(stack, pc=None, analysed=None):
    address_name = stack.pop()
    del cache_accounts[address_name]
    pc += 1
    instructions_executed[str(pc)] = DADDR
    return stack, pc, cache_state, cache_accounts


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

# followed by jumpif
def prep_finalise_data(stack, pc=None, analysed=None):
    # everytime create/delete doc is called, collection name is pushed to stack
    # at this point, the stack should only have collection names
    collection_names = set(stack.get_stack())
    stack.clear_stack()
    if not stack.is_stack_empty():
        return None, None, None, None

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
                # return None, None, None, None
                is_empty = 0
                stack.push(pc+2) # location to return to incase of a jump
                stack.push(name)
                stack.push(key)
                if name == 'sales':
                    stack.push(cache_state[name][key]['tray_no'])
                    stack.push(cache_state[name][key]['tray_price'])
                    stack.push(cache_state[name][key]['buyer'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(cache_state[name][key]['section'])
                    stack.push(5)
                elif name == 'purchases':
                    stack.push(cache_state[name][key]['item_no'])
                    stack.push(cache_state[name][key]['item_price'])
                    stack.push(cache_state[name][key]['item_name'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(cache_state[name][key]['section'])
                    stack.push(5)
                elif name == 'dead_sick':
                    stack.push(cache_state[name][key]['number'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(cache_state[name][key]['section'])
                    stack.push(cache_state[name][key]['location'])
                    stack.push(4)
                elif name == 'eggs_collected':
                    stack.push(cache_state[name][key]['a1'])
                    stack.push(cache_state[name][key]['a2'])
                    stack.push(cache_state[name][key]['b1'])
                    stack.push(cache_state[name][key]['b2'])
                    stack.push(cache_state[name][key]['c1'])
                    stack.push(cache_state[name][key]['c2'])
                    stack.push(cache_state[name][key]['house'])
                    stack.push(cache_state[name][key]['broken'])
                    stack.push(cache_state[name][key]['trays_collected'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(10)
                elif name == 'trades':
                    stack.push(cache_state[name][key]['amount'])
                    stack.push(cache_state[name][key]['from'])
                    stack.push(cache_state[name][key]['to'])
                    stack.push(cache_state[name][key]['sale_hash'])
                    stack.push(cache_state[name][key]['purchase_hash'])
                    stack.push(cache_state[name][key]['date']['unix']+cache_state[name][key]['date']['locale'])
                    stack.push(5)
                else:
                    print("collection name invalid")
                    return None, None, None, None
        
        if is_empty:
            pc += 2
        else:
            pc += 1

    instructions_executed[str(pc)] = PREPFINALISE
    return stack, pc, cache_state, cache_accounts


inst_mapping = {
    str(PUSH): push,
    str(DUP): dup,
    str(ADD): add,
    str(MUL): mul,
    str(SUB): sub,
    str(DIV): div,
    str(EQ): eq,
    str(SWAP): swap,
    str(STOP): stop,
    str(ROOTHASH): root_hash,
    str(JUMPIF): jump_if,
    str(SHA512): sha512,
    str(ISZERO): is_zero,
    str(CONFIRMCACHE): confirm_cache,
    str(UPDATECACHE): update_cache,
    str(STATE): get_state,
    str(EXITLOOP): exit_loop,
    str(PREPFINALISE): prep_finalise_data,
    str(CENTRY): create_entry,
    str(CADDR): create_address,
    str(DADDR): delete_address,
    str(DENTRY): delete_entry,
    str(NOW): timestamp_now
}
