from hashlib import sha256

def key_gen():
    phi = 2
    e = 2
    while gcd(phi, e) != 1 : 
        p = random_prime(2**1024, proof = False)
        q = random_prime(2**1024, proof = False)
        n = p*q
        phi = (p-1) * (q-1)
        e = 65537
    d = inverse_mod(e, phi)
    return (e, d, n, p, q)

def sign(m, d, p, q, n):
    dp = d % (p-1)
    dq = d % (q-1)
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
    #Nous introduisons ici le bug
    sp = ZZ.random_element(p)# Nous simulons ici le bug. Vrai code: power_0mod(h, dp, p)
    sq = power_mod(h, dq, q)
    return crt([sp, sq], [p, q])
def signatureWorking(m, d, p, q, n):
    dp = d % (p-1)
    dq = d % (q-1)
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
 
    sp =  power_mod(h, dp, p)
    
    sq = power_mod(h, dq, q)
    return crt([sp, sq], [p, q])
'''
This function key gens the values we need to test if our hack function is working

'''
def generate():
    (e, d, n, p, q) = key_gen()
    m = b"This message is signed with RSA-CRT!"
    s = sign(m, d, p, q, n)                                                                 # generate signature with the vuln.
    print("Our defined values ----------------------------------------")
    print("e = %s" % str(e))
    print("------------------------------------------------------------------")
    print("n = %s" %str(n))
    print("------------------------------------------------------------------")
    print("s = %s" %s)
    print("------------------------------------------------------------------")
    print("d = %s" %str(d))
    print("------------------------------------------------------------------")
    print("p = %s" %str(p))
    print("------------------------------------------------------------------")
    print("q = %s" %str(q))
    print("------------------------------------------------------------------")                                                          
    print("Hacking our own key @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    print("------------------------------------------------------------------")
    (hacked_d) = hackSignature(e,n,m,s)                                      # hack the signature with our values
    
    if d == hacked_d:
        print("Private key found")
    

'''
This function is designed to validate a signature
'''
def validateSignature(m,s,e,n):
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")   # message hash
    mprime = power_mod(s,e,n)                                   # calculate message hash from signature
    print(f" if {mprime} == {h}")                               # check if the message hash corresponds with the signature
    if mprime == h:
        return true
    return false
def hackSignature(e,n,m,s):
    
    ###### RSA-CRT

    mprime = power_mod(s,e,n)                                   # find corrupted m prime
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")   # message hash
    
    print(f"mprime : {mprime}")
    print("------------------------------------------------------------------")
    print(f"message hash: {h}")
    print("------------------------------------------------------------------")
    p = gcd(h-mprime,n)                                         # exploiting the vulnerability
    q = n/p                                                     # Calculate Q with P from N
    d = power_mod(e,-1, (p-1)*(q-1))                            # Calculate the private key, phi(N) = (p-1) * (q-1)

    print(f"Cracked P = {p}")
    print("------------------------------------------------------------------")
    print(f"Cracked Q = {q}")
    print("------------------------------------------------------------------")
    print(f"Cracked D = {d}")
    print("------------------------------------------------------------------")
    
    test_signature = signatureWorking(m,d,p,q,n)                # Create the real signature

    if validateSignature(m,test_signature,e,n):                 # Validate the signature 
        print("Signature ok")
        return d
    else:
        print("Signature nok")
        return 0,0,0
    

generate()

print("Hacking the challenge @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
print("------------------------------------------------------------------")
e = 65537
n = 8829698272894796058566294092055666782872126452750807746555129369227000637915857695428589221511341057523554836694948298377206605673001847013450476796871448913174360477004444607389087584357727518299033629868519198822751284169469680098414714541716948386952961247701034777505689426686201261498980737011046001071171449279898522731197730323564329841958313813700923015955159238715899303115169749085139629355398114518746006337398240588074810472007815336056659179004878034646656318786354262301047895193398137616079757158792272194731937616111683678235365021658262013896963561471722012329950791120004360807901173024461520224493
m = b'This message is signed with RSA-CRT!'
s = 1190917722554178976753284795976688079717481278145993359514513523002036421742572019056865149314632211957040146691028385960597271303411600301272701748873052408939851883089095533903577536549890067654008607578494850765837313788269107848805351486952352373644128856961650613358088819654810410851390931346123802667127784725039647324201895017876605812491526421344457190986345555060175226121768598324888030825387334263332374598728878741248557873773083893721574459604443324611561844080894155789143922264867919685671883927600397121829193609647416838947723115309462560898899772203749883537650525041944263193976056655064867573514

hackSignature(e,n,m,s)

