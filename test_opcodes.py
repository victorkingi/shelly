import unittest
from vm import VM
from opcodes import *

'''
class TestCreateSaleEntry(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
    

    def test_create_one_sale_entry(self):
        code = [
            [PUSH, 5.0],
            [PUSH, 280.0],
            [MUL],
            [PUSH, 1.0],
            [DUP],
            [PUSH, 'DUKA'],
            [CADDR],
            [PUSH, 'PURITY'],
            [CADDR],
            [PUSH, 'DUKA'],
            [PUSH, 1634774400000.0],
            [PUSH, 'DUKA'],
            [PUSH, 280.0],
            [PUSH, 5.0],
            [PUSH, 5.0],
            [DUP],
            [PUSH, 5.0],
            [SHA512],
            [PUSH, 'PURITY'],
            [NOW],
            [PUSH, 'SELL'],
            [CENTRY],
            [STOP]]
        end_cache_state = { 
            'sales': {
                'new0': {
                    'buyer': 'DUKA',
                    'by': 'PURITY',
                    'date': 1634774400000.0,
                    'section': 'DUKA',
                    'submitted_on': 1.6530634936213117e+18,
                    'tray_no': 5.0,
                    'tray_price': 280.0,
                    'tx_hash': '87068e636618c97364201971dc8af62f70b58986112e34edd751d0b58e0629ea7ef24f2277171766d097c2f95159f11706379d7c883b8a2884a14474c1dfaeb8'
                }
            },
            'purchases': {},
            'eggs_collected': {},
            'dead_sick': {},
            'trades': {}
        }
        end_cache_accounts = { 'DUKA': 1400.0, 'PURITY': 1400.0 }

        vm = VM(code)
        result_state, result_accounts = vm.execute()

        self.assertEqual(result_accounts, end_cache_accounts)
        self.assertEqual(result_state, end_cache_state)
'''

class TestCreateBuyEntry(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
    

    def test_create_one_buy_entry(self):
        code = [
            [PUSH, 10.0],
            [PUSH, 3200.0],
            [MUL],
            [PUSH, 1.0],
            [DUP],
            [PUSH, 'FEEDS'],
            [CADDR],
            [PUSH, 'JEFF'],
            [CADDR],
            [PUSH, 'FEEDS'],
            [PUSH, 1651708800000.0],
            [PUSH, 'LAYERS'],
            [PUSH, 3200.0],
            [PUSH, 10.0],
            [PUSH, 5.0],
            [DUP],
            [PUSH, 5.0],
            [SHA512],
            [PUSH, 'JEFF'],
            [NOW],
            [PUSH, 'BUY'],
            [CENTRY],
            [STOP]]
        end_cache_state = { 
            'purchases': {
                'new0': {
                    'item_name': 'LAYERS',
                    'by': 'JEFF',
                    'date': 1651708800000.0,
                    'section': 'FEEDS',
                    'submitted_on': 1.6530634936213117e+18,
                    'item_no': 10.0,
                    'item_price': 3200.0,
                    'tx_hash': '567a6961458d7b9980cf9988c3bce67396cfcf5e1edaf30b04a8c7a1d47bf1163ee10d32ffb63dc8e611222b8c8029838bdabedc99f1687de43d0bd9c1b251fc'
                }
            },
            'sales': {},
            'eggs_collected': {},
            'dead_sick': {},
            'trades': {}
        }
        end_cache_accounts = { 'FEEDS': 32000.0, 'JEFF': 32000.0 }
        vm = VM(code)

        result_state, result_accounts = vm.execute()

        self.assertEqual(result_accounts, end_cache_accounts)
        self.assertEqual(result_state, end_cache_state)

'''
class TestCreateDeadSickEntry(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
    
    def test_create_one_dead_sick_entry(self):
        code = [
            [PUSH, 'CAGE'],
            [PUSH, 'DEAD'],
            [PUSH, 1651708800000.0],
            [PUSH, 14.0],
            [PUSH, 4.0],
            [DUP],
            [PUSH, 4.0],
            [SHA512],
            [PUSH, 'MISMANAGEMENT'],
            [PUSH, 'IMAGE'],
            [PUSH, 'URL'],
            [PUSH, 'BABRA'],
            [NOW],
            [PUSH, 'DS'],
            [CENTRY],
            [STOP]]
        end_cache_state = { 
            'dead_sick': {
                'new0': {
                    'location': 'CAGE',
                    'by': 'BABRA',
                    'date': 1651708800000.0,
                    'section': 'DEAD',
                    'submitted_on': 1.6530634936213117e+18,
                    'number': 14.0,
                    'image_id': 'IMAGE',
                    'image_url': 'URL',
                    'reason': 'MISMANAGEMENT',
                    'tx_hash': 'fa542f4e6dbc9f17e44f70c8409ca43c82a021eb918568dae51256b9d657d07fc43f6dcdb5defc8c4374249a67564e55ce63347cc1d1a71576cd76c371a58cb1'
                }
            },
            'sales': {},
            'eggs_collected': {},
            'purchases': {},
            'trades': {}
        }
        end_cache_accounts = {}
        vm = VM(code)

        result_state, result_accounts = vm.execute()

        self.assertEqual(result_accounts, end_cache_accounts)
        self.assertEqual(result_state, end_cache_state)
'''

def suite():
    buy_test = TestCreateBuyEntry()
    suite = unittest.TestSuite()
    suite.addTest(buy_test)
    #suite.addTest(TestCreateBuyEntry)
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suite())
