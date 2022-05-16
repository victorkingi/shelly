# Instructions

from opcodes import *
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from util import recalculate_root_hash

cred = credentials.Certificate("core101-3afde-firebase-adminsdk-sxm20-194a475b51.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

CREATE = 'CREATE'
DELETE = 'DELETE'


# Once data is pulled from firestore, a collection could contain more than 10,000 entries.
# To prevent high cost of querying data, cache_state will have a local copy of the whole database
# after a query. Hence, if a new query is made, only compare local hash to cloud hash to find out
# if a change was made, if so, update local cache.
# An optimization would be having the total number of docs locally,  if cloud number greater, then first query
# latest docs, perform merkle proof if it exists locally, if not add them to cache.
# If cloud less than local, then it means a doc was deleted
cache_state = { 'sales': {}, 'purchases': {}, 'eggs_collected': {}, 'dead_sick': {}, 'trades': {} }

def push(stack, elem):
    stack.push(elem)
    return stack

def add(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b + a)
    return stack


def sub(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b - a)
    return stack


def mul(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b * a)
    return stack

def div(stack):
    a = stack.top()
    stack.pop()
    b = stack.top()
    stack.pop()
    stack.push(b / a)
    return stack


# gets all data from a collection and recalculates the state
# it will store retrieved values in a cache and compare the root hash
# each time the function is called. If the root hashes match, we stop,
# else we get a skeleton version of the collection and try to 
# reconstruct the root hash. If we fail, then a normal full query is made
# The purpose of this is to reduce firestore costs and lag when querying
# large amounts of data i.e. 100,000 documents
def aggregate(stack):
    collection_name = stack.top()
    stack.pop()
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
    
    else:
        print("cache exists confirming validity...")
        # check if state hashes match
        root_hash = state_dict['root_hash']
        local_hash = cache_state[collection_name]['state']['root_hash']
        
        if local_hash == root_hash:
            print("hashes match no need for update")
        else:
            get_last_3_state_changes = state_dict['prev_3_states']
            oldest = get_last_3_state_changes['0']
            second = get_last_3_state_changes['1']
            newest = get_last_3_state_changes['2']

            local_oldest = cache_state[collection_name]['state']['prev_3_states']['0']
            local_second = cache_state[collection_name]['state']['prev_3_states']['1']
            local_newest = cache_state[collection_name]['state']['prev_3_states']['2']

            # try applying delete and create operations until hashes match
            if oldest['tx_hash'] != local_oldest.get('tx_hash', False):
                operation_done = oldest['op'] # can be delete or create
                if operation_done == CREATE:
                    cache_state[collection_name][oldest['id']] = {
                        'tx_hash': oldest['tx_hash'],
                        'submitted_on': oldest['submitted_on']
                    }

                    local_oldest = oldest
                elif operation_done == DELETE:
                    del cache_state[collection_name][oldest['id']]
                    local_oldest = oldest

            if second['tx_hash'] != local_second.get('tx_hash', False):
                operation_done = second['op'] # can be delete or create
                if operation_done == CREATE:
                    cache_state[collection_name][second['id']] =  {
                        'tx_hash': second['tx_hash'],
                        'submitted_on': second['submitted_on']
                    }

                    local_second = second
                elif operation_done == DELETE:
                    del cache_state[collection_name][second['id']]
                    local_second = second
        
            if newest['tx_hash'] != local_newest.get('tx_hash', False):
                operation_done = newest['op'] # can be delete or create
                if operation_done == CREATE:
                    cache_state[collection_name][newest['id']] =  {
                        'tx_hash': newest['tx_hash'],
                        'submitted_on': newest['submitted_on']
                    }
                    local_newest = newest
                elif operation_done == DELETE:
                    del cache_state[collection_name][newest['id']]
                    local_newest = newest

            # since we inserted new elements, sort the dict so as to calculate correct hash
            sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1].get('submitted_on', 0))
            cache_state[collection_name] = {k: v for k, v in sorted_tuples}

            # recalculate root hash and compare
            new_root_hash = recalculate_root_hash(collection_name)
            cache_state[collection_name]['state']['root_hash'] = new_root_hash

            if new_root_hash == root_hash:
                print("state updated with a skeleton")

            else:
                # final attempt at preventing a full query, get an array of all ids, perform set difference
                # of local and remote. Time complexity should be O(1) since python uses hash tables for sets

                remote_ids = set(state_dict['all_ids'].keys())
                local_ids = set(cache_state['sales'].keys())

                # in cache but not remote, means a delete happened
                to_delete = local_ids - remote_ids
                if len(to_delete) != 0:
                    for val in to_delete:
                        del cache_state[collection_name][val]
                
                # in remote but not in cache, means a create happened
                to_create = remote_ids - local_ids
                if len(to_create) != 0:
                    for val in to_create:
                        cache_state[collection_name][val] = {
                        'tx_hash': state_dict['all_ids'][val]['tx_hash'],
                        'submitted_on': state_dict['all_ids'][val]['submitted_on']
                    }
                
                # since we inserted new elements, sort the dict so as to calculate correct hash
                sorted_tuples = sorted(cache_state[collection_name].items(), key=lambda item: item[1].get('submitted_on', 0))
                cache_state[collection_name] = {k: v for k, v in sorted_tuples}

                # recalculate root hash and compare
                new_root_hash = recalculate_root_hash(collection_name)
                cache_state[collection_name]['state']['root_hash'] = new_root_hash

                if new_root_hash == root_hash:
                    print("state updated by set difference")
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

                    if local_hash == root_hash:
                        print("full state updated")
                    else:
                        raise RuntimeError("State update failed, hashes don't match")


inst_mapping = {
    str(PUSHNUM): push,
    str(ADD): add,
    str(MUL): mul,
    str(SUB): sub,
    str(DIV): div 
}
