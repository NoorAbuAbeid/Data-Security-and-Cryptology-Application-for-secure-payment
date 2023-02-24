
from os import urandom
import Alice
from binascii import hexlify, unhexlify
import schnorr
from random import randint
import ECDH as ec

from DES_alg import triple_des


print("\n*****************************************************")
print("          Hello to our payment applicatin")
print("*****************************************************")

#define valid users
users=['Noor','Nadeen']
passwords=['4','8']

#loop to check valid username and passwoed
while(True):
    username=input("Enter user name: ")
    password=input("Enter user password: ")
    if(username in users):
        index=users.index(username)
        if(passwords[index]==password):
            break
        else:
            print("\nNpassword incorrect\n")
    else:
        print("\nuser name incorrect\n")
###############################################################################
#                               ECDH algorithm                                #
###############################################################################

print("=========================================================")

print("\nBasepoint:\t", ec.curve.g)
print("=========================================================")
#create private and public key for Alic and Bob
aliceSecretKey, alicePublicKey = ec.make_keypair()
bobSecretKey, bobPublicKey = ec.make_keypair()
#print private and public key for Alic and Bob
print("Alice\'s secret key:\t", aliceSecretKey)
print("Alice\'s public key:\t", alicePublicKey)
print("=========================================================")
print("Bob\'s secret key:\t", bobSecretKey)
print("Bob\'s public key:\t", bobPublicKey)

print("=========================================================")
#calculate sharedkey
sharedSecret1 = ec.scalar_mult(bobSecretKey, alicePublicKey)
sharedSecret2 = ec.scalar_mult(aliceSecretKey, bobPublicKey)

print("Alice\'s shared key:\t", sharedSecret1)
print("Bob\'s shared key:\t", sharedSecret2)

print("=========================================================")
print("The shared value is the x-value: \t", (sharedSecret1[0]))

print("=========================================================")

###############################################################################
#                               3DES algorithm                                #
###############################################################################
#bring the shared key to be used in 3DES algorithm
KEY_IN_STR=str(sharedSecret1[0])
Key_in_byes=bytes(KEY_IN_STR,'ascii')
my_IV = hexlify(urandom(4))  #b'MbQeShVm'
DES_KEY=hexlify(Key_in_byes) 

DES_KEY=DES_KEY[0:24]
msg=input("Enter amount of money: ")

while((len(msg) % 8)):
    msg=input("Enter amount of money (insert a number that multiples of 8): ")
#encryption by 3DES algorithm
datain=str.encode(msg)
myDes=triple_des(DES_KEY,my_IV)
ciphertext = myDes.encrypt(datain,'PAD_PKCS5')
print("the original msg:\n",msg)
print("\nthe encrypt msg:\n",ciphertext)
print("\nthe original key:\n",DES_KEY)

###############################################################################
#                              schnorr signature                              #
###############################################################################
g = 2
p = 2695139 # prime number
secret_key = randint(1000, 1000000)#32991
public_key = pow(g, secret_key, p)
signer = schnorr.SchnorrSigner(key=secret_key, p=p, g=g, hash_func=schnorr.sha256_hash)
signature = signer.sign(str(ciphertext))

# ************** Alice decryption ********************
Alice_verifier=Alice.create_verfier(public_key, p, g)
verified = Alice_verifier.verify(str(ciphertext), signature)
print("verified=" + str(verified))
if(verified==True):
    print("The signature is matched.\nThe current message was received from Bob.")
    res=myDes.decrypt(ciphertext)
    print ("\nthe decrypt msg",res)
else:
    print("The signature is incorrect.\nThe current message was not received from Bob.")


print("\n*****************************************************")

print("     Thank you for using our application")

print("*****************************************************")





