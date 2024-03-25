from Crypto.Cipher import Blowfish
from struct import unpack

def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt_blowfish_cbc(encrypted_message, secret_key):
    iv = encrypted_message[:Blowfish.block_size]
    ciphertext = encrypted_message[Blowfish.block_size:]
    cipher = Blowfish.new(secret_key, Blowfish.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad_data(padded_plaintext)
    return plaintext

# Read the encrypted message from a file
with open("encrypted_message.bin", "rb") as file:
    encrypted_msg = file.read()

# Read the secret key from a file (in a real application, secure key management is crucial)
with open("secret_key.bin", "rb") as file:
    secret_key = file.read()

# Decrypt the encrypted message
decrypted_msg = decrypt_blowfish_cbc(encrypted_msg, secret_key)
print("Decrypted:", decrypted_msg)



# iv = encrypted_message[:Blowfish.block_size]: 
# The first part of the encrypted message is the initialization vector (IV) 
# that was used during the encryption process. The size of the IV is the same as 
# the block size of the Blowfish cipher. This line extracts the IV from the beginning of the encrypted message.

# ciphertext = encrypted_message[Blowfish.block_size:]: 
# After the IV, the rest of the encrypted message is the actual ciphertext (the encrypted data). 
# This line separates the ciphertext from the IV by slicing the encrypted message from the point
# right after the IV to the end.

# cipher = Blowfish.new(secret_key, Blowfish.MODE_CBC, iv): 
# This creates a new Blowfish cipher object, initialized with the same 
# secret key used for encryption and the IV extracted in step 1. The cipher 
# is set to use Cipher Block Chaining (CBC) mode, which requires the IV.

# padded_plaintext = cipher.decrypt(ciphertext): 
# The cipher object is used to decrypt the ciphertext. 
# The output at this stage includes the original plaintext data plus any 
# padding that was added to make the plaintext fit the block size during encryption.

# plaintext = unpad_data(padded_plaintext): 
# Since the decrypted data includes padding, this step removes the padding to 
# restore the original plaintext. It uses the unpad_data function, which looks at the 
# last byte of the decrypted data to determine how many bytes of padding need to be removed and then removes them.
