# Instructions
from opcodes import *
from util import recalculate_root_hash
from functools import reduce

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
    'dead_sick': {}
    'trades': {} 
}
instructions_executed = {}
last_jump = -1                                  # keep track of last location before jump so as to go back once jump is called again
last_instr = ''                                 # last instruction before a jump

def push(stack, elem, pc=None, analysed=None) :
    stack.push(elem)
    pc += 1
    instructions_executed[str(pc)] = PUSH
    return stack, pc


def add(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b + a)
    pc += 1
    instructions_executed[str(pc)] = ADD
    return stack, pc


def sub(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b - a)
    pc += 1
    instructions_executed[str(pc)] = SUB
    return stack, pc


def mul(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b * a)
    pc += 1
    instructions_executed[str(pc)] = MUL
    return stack, pc


def div(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()
    stack.push(b / a)
    pc += 1
    instructions_executed[str(pc)] = DIV
    return stack, pc


def stop(stack, pc=None, analysed=None):
    a = stack.pop()
    if not a:
        return stack, -1
    else:
        # operation failed
        return None, None


def root_hash(stack, pc=None, analysed=None) :
    collection_name = stack.pop()

    stack.push(cache_state[collection_name]['state']['root_hash'])
    pc += 1
    instructions_executed[str(pc)] = ROOTHASH
    return stack, pc


def jump_if(stack, pc=None, analysed=None) :
    cond = stack.pop()

    if cond:
        if CONFIRMCACHE == last_instr:
            last_instr = ''
            print("root hash doesn't match even after full update")
            return None, None
        
        dest = stack.pop() # program counter number
        pc = dest
        instructions_executed[str(pc)] = JUMPIF
        return stack, pc
    else:
        if last_jump != -1:
            pc = last_jump
            last_jump = -1
            instructions_executed[str(pc)] = JUMPIF
            return stack, pc
        
        pc += 1
        instructions_executed[str(pc)] = JUMPIF
        return stack, pc


def sha512(stack, pc=None, analysed=None) :
    m = hashlib.sha512()

    num_of_elements = stack.pop()
    to_hash = ''

    for i in range(num_of_elements):
        val = stack.pop()
        to_hash += val
        print("all hashes:", val)
    
    m.update(to_hash.encode())
    stack.push(m.hexdigest())

    pc += 1
    instructions_executed[str(pc)] = SHA512
    return stack, pc


def is_zero(stack, pc=None, analysed=None) :
    val = stack.pop()

    stack.push(1 if val == 0 else 0)
    pc += 1
    instructions_executed[str(pc)] = ISZERO
    return stack, pc


def eq(stack, pc=None, analysed=None) :
    a = stack.pop()
    b = stack.pop()

    stack.push(1 if a == b else 0)
    pc += 1
    instructions_executed[str(pc)] = EQ
    return stack, pc


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
    return stack, pc


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
        return stack, pc
    else:
        local_hash = cache_state[collection_name]['state']['root_hash']
        if local_hash == state_dict['root_hash']:
            pc += 1
            stack.push(0)
            instructions_executed[str(pc)] = UPDATESTATE
            return stack, pc
        
        pc += 1
        cache_state[collection_name] = {}
        stack.push(collection_name)
        stack.push(analysed['VALID_JUMPDEST'][pc+1]) # this location will have updatecache opcode
        stack.push(1)
        instructions_executed[str(pc)] = UPDATESTATE
        return stack, pc


# attempts to update the cache with latest values. Note that we will rarely need
# to call this function as it loads up a whole collection. Most operations i.e.
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
        return stack, pc
    
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
            return stack, pc
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
                return stack, pc

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
                    return stack, pc

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


inst_mapping = {
    str(PUSH): push,
    str(ADD): add,
    str(MUL): mul,
    str(SUB): sub,
    str(DIV): div,
    str(EQ): eq,
    str(STOP): stop,
    str(ROOTHASH): root_hash,
    str(JUMPIF): jump_if,
    str(SHA512): sha512,
    str(ISZERO): is_zero,
    str(CONFIRMCACHE): confirm_cache,
    str(UPDATECACHE): update_cache,
    str(STATE): get_state
}
