#!/usr/bin/env python

#   Copyright (C) 2015 Roman Pasechnik
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

from __future__ import print_function

from PyKCS11 import *
import binascii

pkcs11 = PyKCS11Lib()
pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib

# get 3rd slot
slots = pkcs11.getSlotList()

for s in slots:
    print(s)

slot = slots[0]


#quit()

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1234", CKU_USER)


keyId = ()


private_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),])

for private_key in private_keys:
  key_info = private_key.to_dict()
  if len(key_info['CKA_LABEL']) > 21:
    print(key_info['CKA_LABEL'])
    print(key_info['CKA_ID'])
    print(len(key_info['CKA_LABEL']))
    print("")

    keyID = key_info['CKA_ID']








# key ID in hex (has to be tuple, that's why trailing comma)
#keyID = (,)

# "Hello world" in hex
toSign = "48656c6c6f20776f726c640d0a"

# find private key and compute signature
print(session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)]))

privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)])[0]
signature = session.sign(privKey, binascii.unhexlify(toSign), Mechanism(CKM_SHA1_RSA_PKCS, None))
print("\nsignature: %s" % binascii.hexlify(bytearray(signature)))

# find public key and verify signature
pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, keyID)])[0]
result = session.verify(pubKey, binascii.unhexlify(toSign), signature, Mechanism(CKM_SHA1_RSA_PKCS, None))
print("\nVerified: %s" % result)

# logout
session.logout()
session.closeSession()
