# %%
from sympy.ntheory.residue_ntheory import primitive_root
from sympy.ntheory import is_primitive_root
import numpy as np
def hashing(txt):
    
    # txt = txt.upper()
    
    ans = 0
    
    for c in txt:
        ans = ans * 26 + (ord(c) - ord('A'))
    
    return ans

def factorization(n):

    if (n == 1):
        return [1]

    lst = []

    factor = 2

    while(n > 1 and factor * factor <= n):
        if (n % factor == 0):

            lst.append(factor)

            while(n % factor == 0):
                n = n // factor

        factor += 1

    if (n != 1):
        lst.append(n)

    return lst
# %%
class ElGammal():
    
    #Khởi tạo gồm p, alpha, a
    def __init__(self, p, alpha = -1, a=100000):
        
        self.p = p
        self.k = p - 2
        self.a = a
        self.alpha = alpha
        
        if (alpha == -1):
            self.alpha = self.find_primitive_element(p)
            
        self.beta = pow(self.alpha, a, p)
        
    
    def find_primitive_element(self, p): 
        
        return primitive_root(self.p)
                
    def encrypt(self, txt):
        
        hash_value = hashing(txt = txt)
        
        
        y1 = pow(self.alpha, self.k, self.p)
        y2 = hash_value * pow(self.beta, self.k, self.p) % self.p
        return (y1, y2)


    def decrypt(self, encrypted_txt):
        
        y1, y2 = encrypted_txt
        
        return y2 * pow(y1, self.p - self.a - 1, self.p) % self.p
    
    def get_public_key(self):
        
        return (self.p, self.alpha, self.beta)
    
    def get_private_key(self):
        return self.a
           
        

# %%
import math

class participant():
    
    
    def __init__(self, letter, p, alpha = -1, a = 100000):
        
        self.elgammal_system = ElGammal(p = p, alpha = alpha, a = a)
        self.p = p
        self.letter = letter
        self.signature = hashing(self.letter)
        
    def find_coprime(self):
        
        for i in range(2, self.p - 2):
            if (math.gcd(i, self.p - 1) == 1):
                return i
    
    def encrypt_letter(self, another):
        encrypted_letter = another.encrypt(txt = self.letter)
        
        return encrypted_letter
        
    def encrypt_signature(self):
        p, alpha, beta = self.elgammal_system.get_public_key()
        a = self.elgammal_system.get_private_key()
        k = self.find_coprime()
        
        hash_value = hashing(txt = self.signature)
        
        gamma = pow(alpha, k, p)
        delta = (hash_value - a * gamma) * pow(k, -1, p - 1) % (p - 1)
        
        
        return (gamma, delta)
    
    def decrypt_letter(self, encrypted_letter):
        
        return self.elgammal_system.decrypt(encrypted_letter)
    
    def decrypt_signature(self, another_public_key, another_signature, encrypted_signature):
        
        p, alpha, beta = another_public_key
        hashing_value = hashing(another_signature)
        
        gamma, delta = encrypted_signature
        
        return pow(beta, gamma, p) * pow(gamma, delta, p) % p == pow(alpha, hashing_value, p)
    

    

# %%
class ElGammal_signature_system():
    
    def __init__(self, p1, p2, letter1, letter2, alpha1 = -1, alpha2 = -1):
        self.participant1 = participant(letter1, p=p1, alpha=alpha1)  # Tạo participant 1 (Alice)
        self.participant2 = participant(letter2, p=p2, alpha=alpha2)  # Tạo participant 2 (Bob)
    
    # Mô phỏng quá trình gửi và nhận chữ ký giữa hai người tham gia
    def send_and_receive(self, sender, receiver):
        print(f"\n--- Quá trình ký và gửi thông điệp từ {sender.letter} đến {receiver.letter} ---")
        
        # Người gửi tạo chữ ký và mã hóa thông điệp
        encrypted_signature = sender.encrypt_signature()
        encrypted_letter = sender.encrypt_letter(receiver.elgammal_system)
        
        print(f"Thông điệp gốc: {sender.letter}")
        print(f"Chữ ký được mã hóa: {encrypted_signature}")
        print(f"Thông điệp được mã hóa: {encrypted_letter}")
        
        # Người nhận giải mã thông điệp và xác minh chữ ký
        decrypted_letter = receiver.decrypt_letter(encrypted_letter)
        is_valid_signature = receiver.decrypt_signature(
            another_public_key=sender.elgammal_system.get_public_key(),
            another_signature=sender.letter,
            encrypted_signature=encrypted_signature
        )
        
        print(f"Thông điệp giải mã: {chr(decrypted_letter + ord('A'))}")
        print(f"Kết quả xác minh chữ ký: {'Hợp lệ' if is_valid_signature else 'Không hợp lệ'}")
    
    # Trường hợp 1: Participant 1 gửi cho Participant 2
    def case_1(self):
        self.send_and_receive(self.participant1, self.participant2)
    
    # Trường hợp 2: Participant 2 gửi cho Participant 1
    def case_2(self):
        self.send_and_receive(self.participant2, self.participant1)
        
  


# p1 = 52786995629017990078783375961280944761228208113475649926725407513191655174698844733077428475647679927182368705701299295149783307413169773988962304654470083227836242729953033004142207979567298543758572036428438833505230009334283511526180873145779
# alpha1 = 2

# p2 = 23926985952326094051246024137239323276330558624000980381219891971255624999836641498557085123807671334334855149420532583754289640256954942752323655022474369
# alpha2 = 3

# # %%
# OwO = ElGammal_signature_system(p1 = p1, p2 = p2, letter1 = "alice", letter2 = "bob", alpha1 = alpha1, alpha2 = alpha2)

# # %%
# OwO.case_1()

# # %%
# OwO.case_2()


