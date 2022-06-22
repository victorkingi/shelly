from firebase_admin import credentials
from firebase_admin import firestore
import firebase_admin
import json
from constants import *
from opcodes import Opcodes
from common_opcodes import CommonOps
from util import get_eggs
from decimal import *
from datetime import datetime

#cred = credentials.Certificate("poultry101-6b1ed-firebase-adminsdk-4h0rk-4b8268dd31.json")
#firebase_admin.initialize_app(cred)
#db = firestore.client()

users = {
    '04d08c83bedef01c48c80c7d8bc4caceb102f32eec4a423136b16b2c5049951884abedcdfdeaf8f9413a7b61e9c607793eacafa7287200cef45f9a4cb4320dd390': 'BABRA',
    '045371c35c8460a5ee16746ae46a29ac03a2eef67da5985377f34491edede0b654c508c851aeded107d7de7d560c21ac759dd547a289fd097ecad5f718c2edcfef': 'VICTOR',
    '043139f6bc7808ece9e00aacd80d5d707406c798a35385105ae72b4404d8281cb2f18423a10e65f8569807ee71d53c8fab08cb5e08fb2813b81cbef6294a7181c6': 'JEFF',
    '04ec74ad5144caefdba5820504a244b1456fdc3bf1031cbe77fc703f61294b42dcce3abe93ff94789d0b65c9b80d667da0708f99f057624e8a8ca64c8272fe66d7': 'PURITY',
    '04fe89d8d08732b07a5be4d0da407019e0a372f119c0979b6a0890da41a02c913d2df5c97c60e63b3220e030901a95cc75988cbf39b9b857e718b4684ba6948a58': 'ANNE',
}

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
                'date': int(vals['date'].timestamp()) if 'date' in vals else int(vals['date_'] / 1000),
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

    elif name == 'blockchain':
        for doc in docs:
            print("checking...", doc.id)
            vals = doc.to_dict()
            txs = vals['chain'][1]['transactions']

            for tx in txs:
                if 'toAddress' not in tx or 'fromAddress' not in tx:
                    continue
                if tx['toAddress'] not in users or tx['fromAddress'] not in users:
                    continue

                valid_date = None
                if isinstance(tx['timestamp'], str):
                    if not tx['timestamp']:
                        valid_date = 1655912781
                    elif tx['timestamp'][-1] == 'Z':
                        valid_date = datetime.fromisoformat(tx['timestamp'][:-1]).timestamp()
                    else:
                        if tx['timestamp'][4].isdigit():
                            valid_date = datetime.strptime(tx['timestamp'][4:], '%d %b %Y').timestamp()
                        else:
                            valid_date = datetime.strptime(tx['timestamp'][4:], '%b %d %Y').timestamp()
                else:
                    valid_date = tx['timestamp']['_seconds']
                
                if valid_date is None:
                    print("none date", tx['timestamp'], type(tx['timestamp']))
                    return

                to_use = {
                    'to': users[tx['toAddress']],
                    'from': users[tx['fromAddress']],
                    'amount': tx['amount'],
                    'by': users[tx['fromAddress']],
                    'date': valid_date,
                    'submitted_on': valid_date
                }

                print(to_use)
                for k in to_use:
                    if to_use[k] is None:
                        print(k, "is none")
                        return
            
                all_docs[doc.id] = to_use
            

    with open(f"{name}.json", "w") as outfile:
        json.dump(all_docs, outfile)

#write_col_docs('blockchain')

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

            if first and name == 'sales':
                first = False
            elif name != 'eggs_collected':
                temp = temp[15:]
            elif name == 'eggs_collected':
                temp = temp[12:]
                
            if name == 'eggs_collected':
                last_instr = list(temp[-19:])
                temp = temp[:-19]
            else:
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

        #print("total entries", i)
        #print("last", last_instr)
        #all_instr.append(last_instr)
        all_instr = flatten(all_instr)
        return all_instr

#fin = create_instr('sales')+create_instr('purchases')+create_instr('eggs_collected')
#print(create_instr('eggs_collected'))
#print(create_instr('trade'))
