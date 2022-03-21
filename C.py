import socket
import sys
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha512
from cryptography.fernet import Fernet

host_ip = '127.0.0.1'
port = 1068

# create socket for the communication with M
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(1)

# create server for M
s.bind((host_ip, port))
s.listen()
m, addr = s.accept()

# public keys
KC = b'123456789fRzh5aPGpecC3p7_rlN5fJqTbqer-V9Tpc='
KM = b'G1SgwYM31fRzh5aPGpecC3p7_rlN5fJqTbqer-V9Tpc='
KPG = b'Q1SgwYM22fRzh5aPGpfcD3p6_rlE5fJqTbqer-X9Tpa='
fernetKM = Fernet(KM)

# SETUP PROTOCOL
# step 1
# key for hybrid encryption
K = Fernet.generate_key()

# cipher
fernetK = Fernet(K)

# encrypt KC with K
encrypted_KC = fernetK.encrypt(KC)

# encrypt K with KM
encrypted_K = fernetKM.encrypt(K)

print("\n cheia KC: ", str(KC))
print("\n cheia K: ", str(K))
print("\n cheia K criptata: ", str(encrypted_K))
print("\n cheia KC criptata: ", str(encrypted_KC))

# send encrypted K to M
m.sendall(encrypted_K)
data = m.recv(1024)

# send encrypted KC to M
m.sendall(encrypted_KC)

# step 2
# receive encrypted_K from M
en_K = m.recv(1024)
print("\n cheia K criptata de la M: ", str(en_K))
m.sendall(str.encode("Received"))

# receive encrypted_sID from M
encrypted_sID = m.recv(1024)
print("\n sID criptat: ", str(encrypted_sID))
m.sendall(str.encode("Received"))

# receive encrypted_signature from M
encrypted_signature = m.recv(1024)
print("\n signature criptata: ", str(encrypted_signature))
m.sendall(str.encode("Received"))

# receive keypair_e from M
keypair_e = m.recv(1024)
keypair_e = int(keypair_e.decode())
m.sendall(str.encode("Received"))

# receive keypair_n from M
keypair_n = m.recv(1024)
keypair_n = int(keypair_n.decode())
m.sendall(str.encode("Received"))

# decrypt sID with the K key
sID = fernetK.decrypt(encrypted_sID)
print("SId: " + str(sID))

# decrypt signature with the K key
signature = int(fernetK.decrypt(encrypted_signature).decode())
print("signature: ", signature)

# check if hash(signature) matches hash(sID)
hash_sID = int.from_bytes(sha512(sID).digest(), byteorder='big')
print("hash sid: ", hash_sID)
hash_signature = pow(signature, keypair_e, keypair_n)
print("hash sig: ", hash_signature)

if hash_sID == hash_signature:
    print("All good sID.")
else:
    print("Something went wrong.")

# EXCHANGE PROTOCOL
# step 3
# PI info
card_number = input("Please enter your card number: ")
card_expiration_date = input("Please enter your card expiration date: ")
challenge_code = input("Please enter the challenge code you received: ")
"""amount = input("Please enter the amount: ")"""
amount = "1001"
client_number = get_random_bytes(16)
print("client number: ", client_number)
mID = b'100'

# PO info
orderID = b'988'

# concatenate PI info
PI = card_number + ',' + card_expiration_date + ',' \
     + challenge_code + ',' + str(sID) + ',' + amount \
     + ',' + str(client_number) + ',' + str(mID)

# hash PI
hash_PI = int.from_bytes(sha512(PI.encode()).digest(), byteorder='big')
print("Hash PI: " + str(hash_PI))

# generate PI signature
keyPairPI = RSA.generate(bits=1024)
PI_signature = pow(hash_PI, keyPairPI.d, keyPairPI.n)
print("PI signature: " + str(PI_signature))

# int to bytes for keyPair elements
keypairPI_e = str(keyPairPI.e)
keypairPI_n = str(keyPairPI.n)

# concatenate PO info
PO = str(orderID) + ',' + str(sID) + ',' \
     + amount + ',' + str(client_number)

# hash PO
hash_PO = int.from_bytes(sha512(PO.encode()).digest(), byteorder='big')
print("Hash PO: " + str(hash_PO))

# generate PO signature
keyPairPO = RSA.generate(bits=1024)
PO_signature = pow(hash_PO, keyPairPO.d, keyPairPO.n)
print("PO signature: " + str(PO_signature))

# generate K
K_PG = Fernet.generate_key()

# ciphers
fernetK_PG = Fernet(K_PG)
fernetKPG = Fernet(KPG)

# encrypt K with KPG
encrypted_K_PG = fernetKPG.encrypt(K_PG)

# encrypt PI with K_PG
encrypted_PI = fernetK_PG.encrypt(PI.encode())

# encrypt PI_signature with K_PG
encrypted_PI_signature = fernetK_PG.encrypt(str(PI_signature).encode())

# encrypt encrypted_PI with KM
twice_encrypted_PI = fernetKM.encrypt(encrypted_PI)

# encrypt encrypted_PI_signature with KM
twice_encrypted_PI_signature = fernetKM.encrypt(encrypted_PI_signature)

# send encrypted_K_PG to M
m.sendall(encrypted_K_PG)
data = m.recv(1024)

# send twice_encrypted_PI to M
m.sendall(twice_encrypted_PI)
data = m.recv(1024)

# send twice_encrypted_PI_signature to M
m.sendall(twice_encrypted_PI_signature)
data = m.recv(1024)

# encrypt PO with KM
encrypted_PO = fernetKM.encrypt(PO.encode())

# encrypt PO_signature with KM
encrypted_PO_signature = fernetKM.encrypt(str(PO_signature).encode())

# send encrypted_PO to M
print(encrypted_PO)
m.sendall(encrypted_PO)
data = m.recv(1024)

# start timer
start = time.perf_counter()

# send encrypted_PO_signature to M
m.sendall(encrypted_PO_signature)
data = m.recv(1024)

# int to bytes for keyPair elements
keypair_e = str(keyPairPO.e)
keypair_n = str(keyPairPO.n)

# send keypair_e to C
m.sendall(keypair_e.encode())
data = m.recv(1024)

# send keypair_n to C
m.sendall(keypair_n.encode())
data = m.recv(1024)

# send keypairPI_e to C
m.sendall(keypairPI_e.encode())
data = m.recv(1024)

# send keypairPI_n to C
m.sendall(keypairPI_n.encode())
data = m.recv(1024)

stop = time.perf_counter()
print(start)
print(stop)

if stop - start < 30:
    print("Waiting time: ", stop - start)

    # receive resp from M
    response_enc = m.recv(1024)
    m.sendall(str.encode("Received"))

    # receive sid from M
    sid_enc = m.recv(1024)
    m.sendall(str.encode("Received"))

    # receive signature from M
    signature_enc = m.recv(1024)
    m.sendall(str.encode("Received"))

    # receive k from M
    k_enc = m.recv(1024)
    m.sendall(str.encode("Received"))

    # decrypt response
    response = fernetK.decrypt(response_enc).decode()
    print("response: ", response)

    # decrypt sid
    sid_from_m = fernetK.decrypt(sid_enc)
    print("sid from m: ", str(sid_from_m))
    # decrypt signature
    sig_from_m = fernetK.decrypt(signature_enc)
    print("sig from m: ", sig_from_m)

    # receive keypair from PG for signature
    keypairPG_e = m.recv(1024)
    keypairPG_e = int(keypairPG_e.decode())
    m.sendall(str.encode("Received"))

    keypairPG_n = m.recv(1024)
    keypairPG_n = int(keypairPG_n.decode())
    m.sendall(str.encode("Received"))

    resp_sid_amount_nc = response + ',' + str(sID) + ',' \
                         + amount + ',' + str(client_number)

    # check signature from M
    hash_resp_sid_amount_nc = int.from_bytes(sha512(
        resp_sid_amount_nc.encode()).digest(), byteorder='big')
    hash_signature_from_m = pow(int(sig_from_m.decode()),
                                keypairPG_e, keypairPG_n)

    if hash_resp_sid_amount_nc == hash_signature_from_m:
        print("All good signature from M.")
    else:
        print("Something went wrong")
    sys.exit()
else:
    # RESOLUTION
    print("TIME OUT")

    # step 7
    info_for_pg = str(sID) + ',' + str(amount) + "," \
                  + str(client_number) + ',' + str(KC)

    # hash info
    hash_info_for_pg = int.from_bytes(sha512(info_for_pg.encode()).digest(),
                                      byteorder='big')

    # generate  signature
    keyPairPG = RSA.generate(bits=1024)
    PG_signature = pow(hash_info_for_pg, keyPairPG.d, keyPairPG.n)

    # encrypt info_for_pg with k for PG
    encrypt_info = fernetK.encrypt(info_for_pg.encode())

    # encrypt signature
    encrypt_sign = fernetK.encrypt(str(PG_signature).encode())

    # encrypt K with KPG
    enc_k = fernetKPG.encrypt(K)

    # create socket for the communication with PG
    try:
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Socket successfully created")
    except socket.error as err:
        print("Socket creation failed with error! Try again.")
        exit(1)

    host_ip1 = '127.0.0.1'
    port1 = 1070

    # create server for PG
    s1.bind((host_ip1, port1))
    s1.listen()
    pg, addr = s1.accept()

    # send info to PG
    pg.sendall(encrypt_info)
    data = pg.recv(1024)

    # send sign to PG
    pg.sendall(encrypt_sign)
    data = pg.recv(1024)

    # send k to pg
    pg.sendall(enc_k)
    data = pg.recv(1024)

    # send keypairs to pg
    keypairPG_e = str(keyPairPG.e)
    # send keypairPI_e to C
    pg.sendall(keypairPG_e.encode())
    data = pg.recv(1024)

    keypairPG_n = str(keyPairPG.n)
    # send keypairPI_e to C
    pg.sendall(keypairPG_n.encode())
    data = pg.recv(1024)

    # step 8
    # receives response from PG
    enc_response = pg.recv(1024)
    pg.sendall(str.encode("Received"))

    # receives sid from pg
    ENC_sid = pg.recv(1024)
    pg.sendall(str.encode("Received"))

    # receives signature from pg
    signature_pg = pg.recv(1024)
    pg.sendall(str.encode("Received"))

    # receives enc k from pg
    enc_k = pg.recv(1024)
    pg.sendall(str.encode("Received"))

    # receive keypair from pg for signature
    keypairPG_e = pg.recv(1024)
    keypairPG_e = int(keypairPG_e.decode())
    pg.sendall(str.encode("Received"))

    keypairPG_n = pg.recv(1024)
    keypairPG_n = int(keypairPG_n.decode())
    pg.sendall(str.encode("Received"))

    # decrypt response
    response = fernetK.decrypt(enc_response)
    print(response.decode())

    # decrypt sid from pg
    sid_from_pg = fernetK.decrypt(ENC_sid)

    # decrypt signature
    sign_from_pg = fernetK.decrypt(signature_pg)

    # check signature from pg
    info_from_pg = response.decode() + ',' + str(sID) + "," \
                   + str(amount) + "," + str(client_number)
    hash_info_pg = int.from_bytes(sha512(info_from_pg.encode()).digest(),
                                  byteorder='big')
    hash_signature_from_pg = pow(int(sign_from_pg.decode()), keypairPG_e,
                                 keypairPG_n)

    if hash_info_pg == hash_signature_from_pg:
        print("All good signature from PG.")
    else:
        print("Something went wrong.")
    sys.exit()
