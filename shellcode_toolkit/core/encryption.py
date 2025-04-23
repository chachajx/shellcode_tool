                                                                                                          
import os                                                                                                 
import binascii                                                                                           
import zlib                                                                                               
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes                              
from cryptography.hazmat.primitives import padding                                                        
from cryptography.hazmat.backends import default_backend                                                  
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4                                          
                                                                                                          
class EncryptionHandler:                                                                                  
    def __init__(self):                                                                                   
        self.current_key = None                                                                           
                                                                                                          
    def generate_key(self, algo):                                                                         
        """生成随机密钥"""                                                                                
        if algo == "XOR":                                                                                 
            self.current_key = os.urandom(16)                                                             
        elif algo == "AES-256":                                                                           
            self.current_key = os.urandom(32)                                                             
        elif algo == "RC4":                                                                               
            self.current_key = os.urandom(16)                                                             
        elif algo == "Huffman":                                                                           
            return None  # Huffman不需要密钥                                                              
        return self.current_key                                                                           
                                                                                                          
    def process_data(self, data, algo, encrypt=True):                                                     
        """加密/解密数据处理"""                                                                           
        if not isinstance(data, bytes):                                                                   
            raise ValueError("输入数据必须是bytes类型")                                                   
                                                                                                          
        if algo == "XOR":                                                                                 
            if not self.current_key:                                                                      
                raise ValueError("请先生成密钥")                                                          
            return self._xor_crypt(data, self.current_key)                                                
        elif algo == "AES-256":                                                                           
            if not self.current_key:                                                                      
                raise ValueError("请先生成密钥")                                                          
            return self._aes_crypt(data, self.current_key, encrypt)                                       
        elif algo == "RC4":                                                                               
            if not self.current_key:                                                                      
                raise ValueError("请先生成密钥")                                                          
            return self._rc4_crypt(data, self.current_key)                                                
        elif algo == "Huffman":                                                                           
            return zlib.compress(data) if encrypt else zlib.decompress(data)                              
        else:                                                                                             
            raise ValueError("不支持的加密算法")                                                          
                                                                                                          
    def _xor_crypt(self, data, key):                                                                      
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])                                 
                                                                                                          
    def _aes_crypt(self, data, key, encrypt):                                                             
        if encrypt:                                                                                       
            iv = os.urandom(16)                                                                           
            padder = padding.PKCS7(128).padder()                                                          
            padded_data = padder.update(data) + padder.finalize()                                         
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())                        
            encryptor = cipher.encryptor()                                                                
            return iv + encryptor.update(padded_data) + encryptor.finalize()                              
        else:                                                                                             
            iv = data[:16]                                                                                
            encrypted = data[16:]                                                                         
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())                        
            decryptor = cipher.decryptor()                                                                
            padded_data = decryptor.update(encrypted) + decryptor.finalize()                              
            unpadder = padding.PKCS7(128).unpadder()                                                      
            return unpadder.update(padded_data) + unpadder.finalize()                                     
                                                                                                          
    def _rc4_crypt(self, data, key):                                                                      
        cipher = Cipher(ARC4(key), mode=None, backend=default_backend())                                  
        encryptor = cipher.encryptor()                                                                    
        return encryptor.update(data)                                                                     
                                                                                                          