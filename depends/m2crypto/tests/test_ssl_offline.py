"""Unit tests for M2Crypto.SSL offline parts

Copyright (C) 2006 Open Source Applications Foundation. All Rights Reserved.

Copyright (C) 2009-2010 Heikki Toivonen. All Rights Reserved.
"""

import unittest, doctest
from M2Crypto.SSL import Checker
from M2Crypto import X509
from M2Crypto import SSL
from test_ssl import srv_host


class CheckerTestCase(unittest.TestCase):
    def test_checker(self):

        check = Checker.Checker(host=srv_host,
                                peerCertHash='7B754EFA41A264AAD370D43460BC8229F9354ECE')
        x509 = X509.load_cert('tests/server.pem')
        assert check(x509, srv_host)
        self.assertRaises(Checker.WrongHost, check, x509, 'example.com')
        
        doctest.testmod(Checker)

    
class ContextTestCase(unittest.TestCase):
    def test_ctx_load_verify_locations(self):
        ctx = SSL.Context()
        self.assertRaises(ValueError, ctx.load_verify_locations, None, None)
        
    def test_map(self):
        from M2Crypto.SSL.Context import map, _ctxmap
        assert isinstance(map(), _ctxmap)
        ctx = SSL.Context()
        assert map()
        ctx.close()
        assert map() is _ctxmap.singleton

    def test_certstore(self):
        ctx = SSL.Context()
        ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
        ctx.load_verify_locations('tests/ca.pem')
        ctx.load_cert('tests/x509.pem')

        store = ctx.get_cert_store()
        assert isinstance(store, X509.X509_Store)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CheckerTestCase))
    suite.addTest(unittest.makeSuite(ContextTestCase))
    return suite    


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
