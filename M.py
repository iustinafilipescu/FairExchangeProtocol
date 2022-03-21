import socket
import sys
from Crypto.PublicKey import RSA
from hashlib import sha512
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes

host_ip = '127.0.0.1'
port = 1068

host_ip1 = '127.0.0.1'
port1 = 1071

KM = b'G1SgwYM31fRzh5aPGpecC3p7_rlN5fJqTbqer-V9Tpc='
KPG = b'Q1SgwYM22fRzh5aPGpfcD3p6_rlE5fJqTbqer-X9Tpa='
mID = b'100'

# ciphers
fernetKM = Fernet(KM)
fernetKPG = Fernet(KPG)

# create socket for the communication with C
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(1)

# M connects to the server made by C
client.connect((host_ip, port))

# SETUP PROTOCOL
# step 1
# M receives the encrypted K from C
encrypted_K = client.recv(1024)
print('\n Received the encrypted key K: ', str(encrypted_K))
client.sendall(str.encode("Received"))

# M receives the encrypted KC from C
encrypted_KC = client.recv(1024)
print('\n Received the encrypted key KC: ', str(encrypted_KC))

# decrypt K with the KM key
K = fernetKM.decrypt(encrypted_K)

# cipher for K
fernetK = Fernet(K)

# decrypt KC with the K key
KC = fernetK.decrypt(encrypted_KC)
fernetKC = Fernet(KC)

print("\n cheia KC:", str(KC))
print("\n cheia K: ", str(K))

# step 2
# generate Sid
sID = get_random_bytes(16)
print("sID: " + str(sID))

# encrypt Sid with K
encrypted_sID = fernetK.encrypt(sID)
print("Enc sID: " + str(encrypted_sID))

# encrypt K with KC
en_K = fernetKC.encrypt(K)

# send encrypted_K to C
client.sendall(en_K)
data = client.recv(1024)

# send encrypted_sID to C
client.sendall(encrypted_sID)
data = client.recv(1024)

# generate hash(Sid)
hash_sID = int.from_bytes(sha512(sID).digest(), byteorder='big')
print("Hash sID: " + str(hash_sID))

# generate SigM(Sid)
keyPair = RSA.generate(bits=1024)
signature = pow(hash_sID, keyPair.d, keyPair.n)

signature = str(signature)
print("SigM: " + str(signature))

# encrypt signature with K
encrypted_signature = fernetK.encrypt(signature.encode())

print("Enc sgn: " + str(encrypted_signature))

# send encrypted_signature to C
client.sendall(encrypted_signature)
data = client.recv(1024)

# int to bytes for keyPair elements
keypair_e = str(keyPair.e)
keypair_n = str(keyPair.n)

# send keypair_e to C
client.sendall(keypair_e.encode())
data = client.recv(1024)

# send keypair_n to C
client.sendall(keypair_n.encode())
data = client.recv(1024)

# EXCHANGE PROTOCOL
# step 3
# M receives the encrypted_K_PG from C
encrypted_K_PG = client.recv(1024)
print('\n Received the encrypted key K_PG: ', str(encrypted_K_PG))
client.sendall(str.encode("Received"))

# M receives the twice_encrypted_PI from C
twice_encrypted_PI = client.recv(1024)
print('\n Received the twice_encrypted_PI: ', str(twice_encrypted_PI))
client.sendall(str.encode("Received"))

# M receives the twice_encrypted_PI_signature from C
twice_encrypted_PI_signature = client.recv(1024)
print('\n Received the twice_encrypted_PI_signature: ', str(twice_encrypted_PI_signature))
client.sendall(str.encode("Received"))

# M receives the encrypted_PO from C
encrypted_PO = client.recv(1024)
print('\n Received the encrypted_PO: ', str(encrypted_PO))
client.sendall(str.encode("Received"))

# M receives the encrypted_PO_signature from C
encrypted_PO_signature = client.recv(1024)
print('\n Received the encrypted_PO_signature: ', str(encrypted_PO_signature))
client.sendall(str.encode("Received"))

# decrypt twice_encrypted_PI with KM
once_encrypted_PI = fernetKM.decrypt(twice_encrypted_PI)

# decrypt twice_encrypted_PI_signature with KM
once_encrypted_PI_signature = fernetKM.decrypt(twice_encrypted_PI_signature)

# decrypt encrypted_PO with KM
PO = fernetKM.decrypt(encrypted_PO)
PO = PO.decode()

# decrypt encrypted_PO_signature with KM
PO_signature = fernetKM.decrypt(encrypted_PO_signature)
PO_signature = int(PO_signature.decode())

# M receives the keypairPO_e from C
keypairPO_e = client.recv(1024)
keypairPO_e = int(keypairPO_e.decode())
client.sendall(str.encode("Received"))

# M receives the keypairPO_n from C
keypairPO_n = client.recv(1024)
keypairPO_n = int(keypairPO_n.decode())
client.sendall(str.encode("Received"))

# check if hash(PO) = hash(PO_signature)
hash_PO = int.from_bytes(sha512(PO.encode()).digest(), byteorder='big')
hash_PO_signature = pow(PO_signature, keypairPO_e, keypairPO_n)

if hash_PO == hash_PO_signature:
    print("All good PO.")
else:
    print("Something went wrong")

# decrypt encrypted_K_PG with KPG
K_PG = fernetKPG.decrypt(encrypted_K_PG)
fernetK_PG = Fernet(K_PG)

# encrypt once_encrypted_PI with KPG
twice_encrypted_PI = fernetKPG.encrypt(once_encrypted_PI)

# encrypt once_encrypted_PI_signature with KPG
twice_encrypted_PI_signature = fernetKPG.encrypt(once_encrypted_PI_signature)

# get amount from PO
separated = PO.split(",")
amount = separated[2]
print("Amount: " + amount)

# get NC from PO
separated = PO.split(",")
NC = separated[3]
print("NC: " + NC)

# sID, KC, amount signature
info = str(sID) + ',' + str(KC) + ',' + amount

# hash info
hash_info = int.from_bytes(sha512(info.encode()).digest(), byteorder='big')
print("Hash info: " + str(hash_info))

# generate info signature
keyPair_info = RSA.generate(bits=1024)
info_signature = pow(hash_info, keyPair_info.d, keyPair_info.n)
print("Info signature: " + str(info_signature))

# encrypt info_signature with KPG
encrypted_info_signature = fernetKPG.encrypt(str(info_signature).encode())

# create socket for the communication with PG
try:
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(1)

# create server for PG
s1.bind((host_ip1, port1))
s1.listen()
pg, addr = s1.accept()

# send twice_encrypted_PI to M
pg.sendall(twice_encrypted_PI)
data = pg.recv(1024)

# send twice_encrypted_PI_signature to M
pg.sendall(twice_encrypted_PI_signature)
data = pg.recv(1024)

# send encrypted_info_signature to M
pg.sendall(encrypted_info_signature)
data = pg.recv(1024)

# M receives the keypairPI_e from C
keypairPI_e = client.recv(1024)
client.sendall(str.encode("Received"))

# M receives the keypairPI_n from C
keypairPI_n = client.recv(1024)
client.sendall(str.encode("Received"))

# send encrypted_K_PG to PG
pg.sendall(encrypted_K_PG)
data = pg.recv(1024)

# send keypairPI_e to PG
pg.sendall(keypairPI_e)
data = pg.recv(1024)

# send keypairPI_n to PG
pg.sendall(keypairPI_n)
data = pg.recv(1024)

# send amount to PG
pg.sendall(amount.encode())
data = pg.recv(1024)

# M receives the response from PG
encrypted_response = pg.recv(1024)
pg.sendall(str.encode("Received"))

# M receives the sid from PG
encrypted_sid_from_pg = pg.recv(1024)
pg.sendall(str.encode("Received"))

# M receives the signature from PG
encrypted_signature_from_pg = pg.recv(1024)
pg.sendall(str.encode("Received"))

# M receives encrypted_k from PG
encrypted_k = pg.recv(1024)
pg.sendall(str.encode("Received"))

# receive keypair from PG for signature
keypairPG_e = pg.recv(1024)
keypairPG_e = int(keypairPG_e.decode())
pg.sendall(str.encode("Received"))

keypairPG_n = pg.recv(1024)
keypairPG_n = int(keypairPG_n.decode())
pg.sendall(str.encode("Received"))

# decrypt response
response = fernetK_PG.decrypt(encrypted_response).decode()

# decrypt sid
sid_from_pg = fernetK_PG.decrypt(encrypted_sid_from_pg).decode()

# decrypt signature
signature_from_pg = fernetK_PG.decrypt(encrypted_signature_from_pg)

# check signature from PG
resp_sid_amount_nc = response + ',' + str(sID) \
                     + ',' + amount+',' + NC
hash_resp_sid_amount_nc = int.from_bytes(sha512(resp_sid_amount_nc.encode()).digest(),
                                         byteorder='big')
hash_signature_from_pg = pow(int(signature_from_pg.decode()), keypairPG_e,
                             keypairPG_n)

if hash_resp_sid_amount_nc == hash_signature_from_pg:
    print("All good signature from PG.")
else:
    print("Something went wrong")

# encrypt signature with K for C
encrypted_sign_pg = fernetK.encrypt(signature_from_pg)

# encrypt response from pg with k For C
encrypted_resp_pg = fernetK.encrypt(response.encode())

# encrypt sid with K for C
encrypted_sid = fernetK.encrypt(sID)

# encrypt K with KC
encrypted_hybrid_k = fernetKC.encrypt(K)

try:
    # send resp to C
    client.sendall(encrypted_resp_pg)
    data = client.recv(1024)

    # send sid to C
    client.sendall(encrypted_sid)
    data = client.recv(1024)

    # send signature to C
    client.sendall(encrypted_sign_pg)
    data = client.recv(1024)

    # send encrypted k with KC to C
    client.sendall(encrypted_hybrid_k)
    data = client.recv(1024)
    keypairPG_e = str(keypairPG_e)

    # send keypairPI_e to C
    client.sendall(keypairPG_e.encode())
    data = client.recv(1024)
    keypairPG_n = str(keypairPG_n)

    # send keypairPI_e to C
    client.sendall(keypairPG_n.encode())
    data = client.recv(1024)
except:
    sys.exit()

sys.exit()
