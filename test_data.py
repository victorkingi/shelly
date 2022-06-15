from firebase_admin import credentials
from firebase_admin import firestore
import firebase_admin
import json
from constants import *
from common_opcodes import *

#cred = credentials.Certificate("poultry101-6b1ed-firebase-adminsdk-4h0rk-4b8268dd31.json")
#firebase_admin.initialize_app(cred)
#db = firestore.client()

def write_col_docs(name):
    collection_ref = db.collection(name)
    docs = collection_ref.stream()
    all_docs = {}

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
            'section': vals['section'].upper() if vals['section'].upper() != "OTHER_SALE" else "OTHER",
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
    
    with open(f"{name}.json", "w") as outfile:
        json.dump(all_docs, outfile)

#write_col_docs('sales')

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
            temp = create_sale_instructions(values=v)
            i += 1
            if not first:
                temp = temp[15:]
            else:
                first = False
            
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
        all_instr.append(last_instr)
        all_instr = flatten(all_instr)
        return all_instr


#create_instr('sales')
