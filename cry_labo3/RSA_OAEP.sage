from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor


MODULE_SIZE = 256 #in bytes
HASH_SIZE = 32 #in bytes
MAX_MESSAGE_SIZE = 221 #in bytes
SEED_SIZE = MODULE_SIZE - HASH_SIZE - MAX_MESSAGE_SIZE -2 #-2 for the 0x01 in padding and the 0x00 in schema


def key_gen():
    phi = 2
    e = 2
    while gcd(phi, e) != 1 : 
        p = random_prime(2**1024)
        q = random_prime(2**1024)
        n = p*q
        phi = (p-1) * (q-1)
        e = 65537
    d = inverse_mod(e, phi)
    return (e, d, n)


HL = SHA256.new(data = b"").digest() #Constant for padding
    
def mgf(seed, length):
    #This function is correct and you don't need to look at it
    return MGF1(seed, length, SHA256)

def encrypt_OAEP(m, e, n):
    if len(m) > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")
    #pad message
    zeros = b"\x00" * (MODULE_SIZE - HASH_SIZE  - SEED_SIZE - len(m) - 2)
    padded_m = HL + zeros + b"\x01" + m
    seed = get_random_bytes(SEED_SIZE)
    masked_DB = strxor(padded_m, mgf(seed, len(padded_m)))
    print(len(masked_DB))
    masked_seed = strxor(seed, mgf(masked_DB, len(seed)))
    to_encrypt = int.from_bytes(masked_seed + masked_DB, byteorder="big")
    #textbook RSA
    return power_mod(to_encrypt, e, n)
    
def textbook_rsa_decrypt(c,d,n):
    return int(power_mod(c,d,n)).to_bytes(MODULE_SIZE,byteorder="big")
    
def unpad(message):
    padded_m = message[HASH_SIZE:]              # remove hash
    ret_m = b''
    for i in range(len(padded_m)):              # parse everything until = 1
        if 1 == padded_m[i]:
            ret_m = padded_m[i+1:]              # select the message
    return ret_m                                # return the message

def decrypt_OAEP(c,d,n):

    masked_message = textbook_rsa_decrypt(c,d,n)    # decrypt with textbook rsa

    masked_DB = masked_message[SEED_SIZE+1:]        # recover masked DB

    masked_seed = masked_message[1:SEED_SIZE+1]     # recover masked seed

    mgf_db = mgf(masked_DB,len(masked_seed))        # pass through function to later find the seed

    seed = strxor(masked_seed, mgf_db)              # calculate seed

    hashed_seed = mgf(seed,len(masked_DB))          # hash the seed 

    hash_padded_m = strxor(hashed_seed,masked_DB)   # calculate the original hash+pad+message

    return unpad(hash_padded_m)                     # remove pad
    '''
    This function is designed to encrypt with a seed of choice
    '''
def reversed_RSA_AEP(m,e,n,seed):
    seed = seed.to_bytes(1, byteorder="big")
    if len(m) > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")

    zeros = b"\x00" * (MODULE_SIZE - HASH_SIZE  - SEED_SIZE - len(m) - 2)
    padded_m = HL + zeros + b"\x01" + m
    masked_DB = strxor(padded_m, mgf(seed, len(padded_m)))
    masked_seed = strxor(seed, mgf(masked_DB, len(seed)))
    to_encrypt = int.from_bytes(masked_seed + masked_DB, byteorder="big")

    return power_mod(to_encrypt, e, n)
def bruteForceAttack(c, e, n):
    print(f"Searching for {c}")  # Grade to find
    print("---------------------------------------------------------------")
    for i in range(256):        
        for j in range(61):
            grade_to_test = round(j * 0.1, 1)
            grade_to_test_bytes = str(grade_to_test).encode()  # Convert to string, then to bytes
            print(f"Grade to test {grade_to_test}")
            
            try:
                find = reversed_RSA_AEP(grade_to_test_bytes, e, n, i)
                print(f"Current find : {find}")                
                if c == find:
                    print(f"Found grade: {grade_to_test}")
                    return grade_to_test                        # return grade
            except ValueError as e:
                print(f"Error encrypting grade {grade_to_test}: {e}")

test_message = b"Your boy from the streets"

e,d,n = key_gen()
c = encrypt_OAEP(test_message,e,n)
print(c)
message = decrypt_OAEP(c,d,n)
print(message)

###### RSA-OAEP

e = 65537
n = 9718745065523854527730659884553057867893768207269780500592090564811023220630164484314466599724407230488505634301369272976030196461204805278557371111280519851190833531615348179589149837332953686519312507122369015861402917467966389593485414455227012317198600322752050891028023500360102706039355697765935681856946562462360188282991706117109071069397570878896103534312961394214752723448341118501056552269391474635921422238774780763293743259547491537841175436302237150904789950674994940724996664109559885120013340897400427929751532542307298254063976900078103484678268826927077844343564569573329136972799473986597506353863
c = 3780454515278853512568906300840780068561425889842879770114754992038356575586980655087114865442890442376892804480473952906868689342267777585413771773483596579447303781190956369886821924964534003671216371612728618894640364837911040919366537339724533562771165905700441748970589553481332767636643154703589264492441186398406912479796361558150094907041167386094046735128413985088334972852161898813121149583846951611646066433300492809602770574588690275465059935844767724844567730000180864515973052604829885914664701762600241117349941063119138540289991599461973855722609025821163307023847440108800662459556975401582335103771


res = bruteForceAttack(c,e,n)
print(f"Cracked RSA OAEP Encryption, decrypted data is : {res}")