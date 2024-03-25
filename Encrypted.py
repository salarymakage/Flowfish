from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from struct import pack

def pad_data(data):
    block_size = Blowfish.block_size
    padding_length = block_size - len(data) % block_size
    padding = pack('b' * padding_length, *[padding_length] * padding_length)
    return data + padding   

def encrypt_blowfish_cbc(plaintext_bytes, secret_key):
    cipher = Blowfish.new(secret_key, Blowfish.MODE_CBC) #Cipher Block Chaining
    padded_plaintext = pad_data(plaintext_bytes)
    encrypted_message = cipher.iv + cipher.encrypt(padded_plaintext)
    return encrypted_message

# Example usage
secret_key = get_random_bytes(Blowfish.key_size[0])  # Generate a random Blowfish key
plaintext = b'Hellowerefw!'

# Encrypt the plaintext
encrypted_msg = encrypt_blowfish_cbc(plaintext, secret_key)
print("Encrypted:", encrypted_msg)

# Save the encrypted message to a file
with open("encrypted_message.bin", "wb") as file:
    file.write(encrypted_msg)

# Optionally, save the secret key to a file (in a real application, secure key management is crucial)
with open("secret_key.bin", "wb") as file:
    file.write(secret_key)


    # block_size = Blowfish.block_size
    # this line is going to take block size in blowfish which is typically 8 bytes. 
    # This size is important to understand how much padding needs to be added to the data.

    # padding_length = block_size - len(data) % block_size
    # To figure out how much padding is needed, this line calculates 
    # the remainder of the data length divided by the block size.
    # Subtracting this remainder from the block size gives the padding length.
    # If the data length is already a multiple of the block size, this calculation results in a full block 
    # of padding (equal to the block size), ensuring that the padding can always be correctly removed.

    # *[padding_length] * padding_length: 
    # This is the data to be packed according to the specified format. 
    # It creates a list where the number padding_length is repeated padding_length times.
    # This means we want to pack a sequence of bytes, each set to the value of padding_length.

    # pack('b' * padding_length, *[padding_length] * padding_length)
    # Combining the format string and the data list, pack converts the data into a bytes object 
    # where each byte has the value of padding_length. This bytes object is used as padding to ensure 
    # the data's length is a multiple of the block size for encryption.
    
    # cipher = Blowfish.new(secret_key, Blowfish.MODE_CBC)
    # This line creates a new Blowfish cipher object.
    # provide it with two things: a secret_key and the mode of operation Blowfish.MODE_CBC
    # is a way of encrypting that makes each block of plaintext depend on the previous one for added security.
    # When the cipher is created, it also generates a random Initialization Vector (IV),
    # which is used to make the encryption even more secure.

    # padded_plaintext = pad_data(plaintext_bytes)
    # Before encrypting, the data needs to be a certain length (a multiple of the block size).
    # If it's not, we add some extra bytes to the end until it is. 
    # The encrypted data by itself isn't enough to decrypt it later;
    # you also need the IV that was used during encryption. 
    # This line takes the IV (cipher.iv) and adds it to the beginning of the encrypted data. 
    # when you or someone else needs to decrypt the data, the IV is right there, ready to be used.
