# import argparse
# import salsa20
# import binascii

# from salsa20 import XSalsa20_xor
# from os import urandom
# from Crypto.Util.number import inverse
# import sympy
# import random
# from binascii import hexlify, unhexlify
# import el_gamal
# import public


# public.m =1546525
# public.Alice_key=random.randint(int(m/2),m)
# Alice_private_key = random.randint(int(m/2),m)

# def generate_param():
#     m =154456525
#     p = sympy.randprime(m*2, m*4)
#     g = sympy.randprime(int(m/2), m)
#     h = el_gamal.shared_secret(public.g,Alice_private_key,public.p)
#     return p,g,h

# def decrypt_el_gamal():
#     dm = el_gamal.decrypt(Alice_private_key,public.C1,public.C2,public.p)
#     res=bytes(dm)
#     print(res)
#     # print("Decrypted Integer (dm): {}".format(dm))
#     # x = format(dm, 'x')
#     # print("Decrypted Hex (x)     : {}".format(x))
#     # message = unhexlify(x)
#     # print("Decrypted Message     : {}".format(message))
    
    
#     print(XSalsa20_xor(public.ciphertext, public.IV, res).decode())
from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal
import schnorr

def create_keys():
    pri_key,pub_key= gen_keypair(Curve25519)# the reciver side (decryption)
    return pri_key,pub_key

 
def create_verfier(public_key, p, g):
    verifier = schnorr.SchnorrVerifier(keys=public_key, p=p, g=g, hash_func=schnorr.sha256_hash)
    return verifier

    
# plaintext = b"I am plaintext."
# # Generate key pair
# pri_key, pub_key = gen_keypair(Curve25519)# the reciver side (decryption)
# # Encrypt using ElGamal algorithm
# cipher_elg = ElGamal(Curve25519)
# C1, C2 = cipher_elg.encrypt(plaintext, pub_key)
# # Decrypt
# print(plaintext)
# new_plaintext = cipher_elg.decrypt(pri_key, C1, C2)

# print(new_plaintext == plaintext)
# # >> True










