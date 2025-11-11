from Crypto.Cipher import AES
from Crypto import Random

class AESCipher:
    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv

    def AES_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext

    def AES_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    def pad(data: bytes, block_size: int = 16) -> bytes:
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(data: bytes) -> bytes:
        padding_length = data[-1]
        return data[:-padding_length]
    
    def run(self) -> None:
        key = Random.get_random_bytes(16)
        iv = Random.get_random_bytes(16)
        plaintext = b'This is a secret message.'
        
        #padded_plaintext = self.pad(plaintext)
        ciphertext = self.AES_encrypt(plaintext, key, iv)
        decrypted_padded_plaintext = self.AES_decrypt(ciphertext, key, iv)
        decrypted_plaintext = self.unpad(decrypted_padded_plaintext)
        
        print(f'Original Plaintext: {plaintext}')
        print(f'Ciphertext: {ciphertext}')
        print(f'Decrypted Plaintext: {decrypted_plaintext}')


aes_cipher = AESCipher(key=b'', iv=b'')
aes_cipher.run()