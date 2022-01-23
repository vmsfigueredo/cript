from Crypto.Cipher import AES
from secrets import token_bytes


secret = token_bytes(16);

print(f'Secret: {secret}')

def encrypt(msg):
    cipher = AES.new(secret, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(secret, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('utf-8')
    except:
        return 'Not able to decrypt'
    
nonce, ciphertext, tag = encrypt(input('Enter a message: '))

plaintext = decrypt(nonce, ciphertext, tag)
print(f"\nCipher text: {ciphertext}\n")
print(f"Plain text: {plaintext}")