from firebase_admin import credentials
from firebase_admin import firestore
import firebase_admin
import json
from constants import *
from opcodes import Opcodes
from common_opcodes import CommonOps
from util import get_eggs
from decimal import *

cred = credentials.Certificate("poultry101-6b1ed-firebase-adminsdk-4h0rk-4b8268dd31.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

def write_col_docs(name):
    collection_ref = db.collection(name)
    docs = collection_ref.stream()
    all_docs = {}

    if name == 'sales':
        for doc in docs:
            print("checking...", doc.id)
            vals = doc.to_dict()

            if vals['section'].upper() == "THIKA_FARMERS":
                vals['section'] = "THIKAFARMERS"
                vals['buyerName'] = "THIKAFARMERS"
            
            if vals['buyerName'].upper() == "SANG":
                vals['buyerName'] = "SANG'"
            
            if vals['buyerName'].upper() == "ETON ":
                vals['buyerName'] = "ETON"
            
            if vals['buyerName'].upper() == "BUI-LYNN":
                vals['buyerName'] = "LYNN"
            
            if vals['buyerName'].upper() == "LANGAT":
                vals['buyerName'] = "LANG'AT"
            
            if vals['buyerName'].upper() == "LANGAT ":
                vals['buyerName'] = "LANG'AT"
            
            if vals['buyerName'].upper() == "KINYAJUI":
                vals['buyerName'] = "KINYANJUI"
            
            if vals['buyerName'].upper() == "JEFF FORGOT BUYER NAME" or vals['buyerName'].upper() == "JEFF FORGOT SALE OF 3,200":
                vals['buyerName'] = "FORGOTJEFF"

            to_use = {
                'tray_no': float(vals['trayNo']),
                'tray_price': float(vals['trayPrice']),
                'amount': vals['trayNo']*vals['trayPrice'] if (isinstance(vals['trayNo'], int) or isinstance(vals['trayNo'], float)) and (isinstance(vals['trayPrice'], int) or isinstance(vals['trayPrice'], float)) else float(vals['trayNo'])*float(vals['trayPrice']),
                'section': vals['section'].upper() if vals['section'].upper() != "OTHER_SALE" else "SOTHER",
                'by': vals['submittedBy'].upper(),
                'date': int(vals['date'].timestamp()),
                'buyer': vals['buyerName'].upper(),
                'submitted_on': int(vals['submittedOn'].timestamp())
            }
            if to_use['buyer'] not in VALID_BUYERS and to_use['buyer'] not in VALID_SELL_SECTIONS:
                print("buyer", to_use, "does not exist")
                return

            print(to_use)
            for k in to_use:
                if to_use[k] is None:
                    print(k, "is none")
                    return
            all_docs[doc.id] = to_use
    
    elif name == 'purchases':
        for doc in docs:
            print("checking...", doc.id)
            vals = doc.to_dict()

            to_use = {
                'item_no': float(vals['objectNo']),
                'item_price': float(vals['objectPrice']),
                'amount': vals['objectNo']*vals['objectPrice'] if (isinstance(vals['objectNo'], int) or isinstance(vals['objectNo'], float)) and (isinstance(vals['objectPrice'], int) or isinstance(vals['objectPrice'], float)) else float(vals['objectNo'])*float(vals['objectPrice']),
                'section': vals['section'].upper() if vals['section'].upper() != "OTHER_BUY" else "POTHER",
                'by': vals['submittedBy'].upper(),
                'date': int(vals['date'].timestamp()),
                'item_name': vals['itemName'].upper(),
                'submitted_on': int(vals['submittedOn'].timestamp())
            }
            if to_use['item_name'] == 'LAYERS ':
                to_use['item_name'] = 'LAYERS'
            if to_use['section'] == 'OTHER_PURITY':
                to_use['section'] = 'PURITY'
            if to_use['item_name'] == 'LAYERS LAST BALANCE FROM PREVIOUS DATABASE':
                continue
            if to_use['item_name'] == 'PREVIOUS DATABASE UPDATE':
                continue

            if to_use['section'] not in VALID_BUY_SECTIONS:
                print("section", to_use, "does not exist")
                return
            
            if to_use['section'] == "FEEDS" and to_use['item_name'] not in ["LAYERS", "CHICK"]:
                print("item name", to_use, "does not exist")
                return

            print(to_use)
            for k in to_use:
                if to_use[k] is None:
                    print(k, "is none")
                    return
            all_docs[doc.id] = to_use

    elif name == 'eggs_collected':
        for doc in docs:
            print("checking...", doc.id)
            vals = doc.to_dict()

            to_use = {
                'a1': int(vals['a1']) if 'a1' in vals else int(vals['A 1']),
                'a2': int(vals['a2']) if 'a2' in vals else int(vals['A 2']),
                'b1': int(vals['b1']) if 'b1' in vals else int(vals['B 1']),
                'b2': int(vals['b2']) if 'b2' in vals else int(vals['B 2']),
                'c1': int(vals['c1']) if 'c1' in vals else int(vals['C 1']),
                'c2': int(vals['c2']) if 'c2' in vals else int(vals['C 2']),
                'broken': int(vals['broken']),
                'house': int(vals['house']),
                'trays_collected': vals['trays_store'] if 'trays_store' in vals else '',
                'by': vals['submittedBy'].upper(),
                'date': int(vals['date'].timestamp()) if 'date' in vals else int(vals['date_']),
                'submitted_on': int(vals['submittedOn'].timestamp())
            }

            if not to_use['trays_collected']:
                amount = to_use['a1'] + to_use['a2'] + to_use['b1'] + to_use['b2'] + to_use['c1'] + to_use['c2'] + to_use['house']
                to_use['trays_collected'] = get_eggs(Decimal(amount))[0]

            print(to_use)
            for k in to_use:
                if to_use[k] is None:
                    print(k, "is none")
                    return
            all_docs[doc.id] = to_use


    with open(f"{name}.json", "w") as outfile:
        json.dump(all_docs, outfile)

#write_col_docs('eggs_collected')

def flatten(xss):
    return [x for xs in xss for x in xs]

def create_instr(name):
    with open(f'{name}.json') as json_file:
        data = json.load(json_file)
        all_instr = []
        first = True
        last_instr = []
        i = 0

        for k, v in data.items():
            common_ops = CommonOps()
            method_name = f'create_{name}_instructions'
            method = getattr(common_ops, method_name, common_ops.no_create_op)
            temp = method(values=v)
            i += 1

            if not first:
                temp = temp[15:]
            elif first and name == 'sales':
                first = False
            elif name != 'sales':
                temp = temp[15:]
            
            
            last_instr = list(temp[-31:])
            temp = temp[:-31]
                
            all_instr.append(temp)
            jumpif = 0
            k = 0
            for _ in temp:
                if k >= len(temp):
                    break
                if temp[k] == Opcodes.JUMPIF.value:
                    jumpif += 1
                elif temp[k] == Opcodes.JUMPDEST.value:
                    jumpif -= 1

                if temp[k] == Opcodes.PUSH.value:
                    k += 2
                else:
                    k += 1

            if jumpif != 0:
                print("final", jumpif)
                raise RuntimeError("Invalid number of jumpif and jumpdest")

        print("total entries", i)
        #print("last", last_instr)
        #all_instr.append(last_instr)
        all_instr = flatten(all_instr)
        return all_instr

#create_instr('')

#print(create_instr('sales')+create_instr('purchases'))
