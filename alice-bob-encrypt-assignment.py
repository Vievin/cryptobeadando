from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import os
from Crypto import Random


# Bob publikus kulcsa, amit elküld Alice-nek


def newkeys(keysize):
   random_generator = Random.new().read
   key = RSA.generate(keysize, random_generator)
   private, public = key, key.publickey()
   return public, private
# csak a két nagy prímszám legenerálása több oldal lenne, úgyhogy leegyszerűsítettem >.>

def Alice_symmetric_key(publickey):
    AES_key_length = 16 
    secret_key = os.urandom(AES_key_length) # Alice titkos kulcsa
    cipher = PKCS1_OAEP.new(publickey)
    ciphertext = cipher.encrypt(secret_key) # Alice Bob kulcsával titkosítja a saját titkos kulcsát
    return ciphertext, secret_key
# Alice elküldi a Bob publikus RSA kulcsával titkosított AES kulcsot Bobnak

def decrypt(ciphertext, priv_key):
   cipher = PKCS1_OAEP.new(priv_key)
   text = cipher.decrypt(ciphertext)
   return text
#Bob un-titkosítja a kulcsot

def reencrypt(message, key):
    cipher = Alice_symmetric_key.secret_key()
    ciphertext = cipher.encrypt(message) # Bob az Alice-től kapott kulccsal titkosítja az üzenetet
    return ciphertext

BobpubKey, BobprivKey = newkeys(2048) # Bob legyártja a kulcspárját
print(f"Public key:  (n={hex(BobpubKey.n)}, e={hex(BobpubKey.e)})")
encrypted_secret_key, secret_key = Alice_symmetric_key(BobpubKey) # Alice megkapja és letitkosítja a saját kulcsát
Symm_key = decrypt(encrypted_secret_key, BobprivKey) # Bob ezt megkapja és un-titkosítja
Hello_message = reencrypt("Hello!", Symm_key) # Bob elküldi a hellot
Hello_message_decoded = decrypt(Hello_message, Symm_key) # Alice elolvassa a levelet
print(Hello_message_decoded)



#   Alice szól Bob-nak, hogy levelezni szeretne vele.
#    Bob küld egy publikus asszimmertrikus RSA kulcsot Alice-nek
#    Alice generál egy saját szimmetrikus kulcsot, majd ezt titkosítja a Bob-tól származó publikus kulccsal.
#    Bob megkapja és a kulcshoz tartozó privát kulccsal ezt dekódolja
#    Végül ennek használatával (a decrypt-elt szimmetrikus kulcs) küld egy "Hello!" üzenetet vissza Alice-nek.
#    Alice a szimmetrikus kulccsal képes ezt dekódolni és elolvasni.