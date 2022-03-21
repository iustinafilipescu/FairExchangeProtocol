import socket
import sys
import time
from Crypto.PublicKey import RSA
from hashlib import sha512
from cryptography.fernet import Fernet
import psycopg2

host_ip = '127.0.0.1'
port = 1071

KPG = b'Q1SgwYM22fRzh5aPGpfcD3p6_rlE5fJqTbqer-X9Tpa='
KM = b'G1SgwYM31fRzh5aPGpecC3p7_rlN5fJqTbqer-V9Tpc='

# ciphers
fernetKPG = Fernet(KPG)
fernetM = Fernet(KM)

# create socket for the communication with M
try:
    m = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(1)

# PG connects to the server made by M
m.connect((host_ip, port))

# PG receives twice_encrypted_PI from M
twice_encrypted_PI = m.recv(1024)
m.sendall(str.encode("Received"))

# PG receives twice_encrypted_PI_signature from M
twice_encrypted_PI_signature = m.recv(1024)
m.sendall(str.encode("Received"))

# PG receives encrypted_info_signature from M
encrypted_info_signature = m.recv(1024)
m.sendall(str.encode("Received"))

# PG receives the encrypted_K_PG from M
encrypted_K_PG = m.recv(1024)
m.sendall(str.encode("Received"))

# decrypt encrypted_K_PG with KPG
K_PG = fernetKPG.decrypt(encrypted_K_PG)

# cipher
fernetK = Fernet(K_PG)

# decrypt twice_encrypted_PI with KPG
once_encrypted_PI = fernetKPG.decrypt(twice_encrypted_PI)

# decrypt once_encrypted_PI with K
PI = fernetK.decrypt(once_encrypted_PI)

# decrypt twice_encrypted_PI_signature with KPG
once_encrypted_PI_signature = fernetKPG.decrypt(twice_encrypted_PI_signature)

# decrypt once_encrypted_PI_signature with K
PI_signature = fernetK.decrypt(once_encrypted_PI_signature)

# decrypt encrypted_info_signature with KPG
info_signature = fernetKPG.decrypt(encrypted_info_signature)

# PG receives the keypairPI_e from M
keypairPI_e = m.recv(1024)
keypairPI_e = int(keypairPI_e.decode())
m.sendall(str.encode("Received"))

# PG receives the keypairPI_n from M
keypairPI_n = m.recv(1024)
keypairPI_n = int(keypairPI_n.decode())
m.sendall(str.encode("Received"))

# check if hash(PI) = hash(PI_signature)
hash_PI_signature = pow(int(PI_signature.decode()), keypairPI_e, keypairPI_n)
hash_PI = int.from_bytes(sha512(PI).digest(), byteorder='big')

if hash_PI == hash_PI_signature:
    print("All good PI.")
else:
    print("Something went wrong.")

# get PI info
PI = PI.decode()
separated = PI.split(",")
card_number = separated[0]
card_expiration_date = separated[1]
challenge_code = separated[2]
sID = separated[3]
amount = separated[4]
client_number = separated[5]
mID = separated[6]

# database connection
database = psycopg2.connect("dbname=postgres user=postgres "
                            "password=mariaB2000")

database = psycopg2.connect(host="localhost",
                            database="postgres",
                            user="postgres",
                            password="mariaB2000")

# database query
cursor = database.cursor()
query = "SELECT balance FROM public.userCredentials " \
        "WHERE card_number = %s" \
        "AND card_expiration_date = %s" \
        "AND challenge_code = %s;"

cursor.execute(query, (card_number, card_expiration_date,
                       challenge_code,))
records = cursor.fetchall()

response = ""

# check if the client info is correct
if len(records) == 0:
    response = "Great"
    print("There is no client with this info.")
else:
    response = "Wrong credentials"
    print("Found the client with this info.")

# PG receives the amount from M
amount = m.recv(1024)
amount = int(amount.decode())
m.sendall(str.encode("Received"))

# check if the client has at least amount of money in their account
balance = records[0][0]
if amount > balance and len(records) > 0:
    response = "Not enough money in your account"
    print("Your balance is lower than the amount of money you want to spend.")
elif amount <= balance and len(records) > 0:
    response = "Great"
    print("Your balance is high enough to spend the amount of money "
          "you want to spend.")

info = response+',' + str(sID) + ',' \
       + str(amount) + ',' + str(client_number)

# hash info
hash_info = int.from_bytes(sha512(info.encode()).digest(), byteorder='big')
print("Hash info: " + str(hash_info))

# generate info signature
keyPair_info = RSA.generate(bits=1024)
info_signature = pow(hash_info, keyPair_info.d, keyPair_info.n)
print("Info signature: " + str(info_signature))

# encrypt response
encrypted_response_k = fernetK.encrypt(response.encode())

# encrypt SID
encrypted_sid_k = fernetK.encrypt(sID.encode())

# encrypt info_signature
encrypted_signature_k = fernetK.encrypt(str(info_signature).encode())

# encrypt K with KM
encrypted_K = fernetM.encrypt(KPG)

# send encrypted response to M
m.sendall(encrypted_response_k)
data = m.recv(1024)

# send encrypted sid to M
m.sendall(encrypted_sid_k)
data = m.recv(1024)

# send encrypted info signature to M
m.sendall(encrypted_signature_k)
data = m.recv(1024)

# send encrypted_k to M
m.sendall(encrypted_K)
data = m.recv(1024)
keypair_e = str(keyPair_info.e)

# send keypairPI_e to M
m.sendall(keypair_e.encode())
data = m.recv(1024)
keypair_n = str(keyPair_info.n)

# send keypairPI_e to M
m.sendall(keypair_n.encode())
data = m.recv(1024)

# RESOLUTION
# step 2
host_ip2 = '127.0.0.1'
port2 = 1070

# create socket for the communication with C
try:
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error! Try again.")
    exit(1)

# PG connects to the server made by C
try:
    time.sleep(5)
    c.connect((host_ip2, port2))
except:
    sys.exit()

# receives info from C
info_C = c.recv(1024)
c.sendall(str.encode("Received"))

# receives signature from C
signature_C = c.recv(1024)
c.sendall(str.encode("Received"))

# receives enc k from C
enc_k = c.recv(1024)
c.sendall(str.encode("Received"))

# receive keypair from C for signature
keypairC_e = c.recv(1024)
keypairC_e = int(keypairC_e.decode())
c.sendall(str.encode("Received"))

keypairC_n = c.recv(1024)
keypairC_n = int(keypairC_n.decode())
c.sendall(str.encode("Received"))

# decrypt K with KPG
K = fernetKPG.decrypt(enc_k)
fernetKfromC = Fernet(K)

# decrypt info
info_from_c = fernetKfromC.decrypt(info_C).decode()

PUBKC = b'123456789fRzh5aPGpecC3p7_rlN5fJqTbqer-V9Tpc='
fernetKC = Fernet(PUBKC)

# decrypt sign from C
signature_from_c = fernetKfromC.decrypt(signature_C)

# check signature from C
hash_info_c = int.from_bytes(sha512(info_from_c.encode()).digest(),
                             byteorder='big')
hash_signature_from_c = pow(int(signature_from_c.decode()), keypairC_e,
                            keypairC_n)

if hash_info_c == hash_signature_from_c:
    print("All good signature from C.")
else:
    print("Something went wrong")

# step 8
# encrypt response with k
enc_response = fernetKfromC.encrypt(response.encode())

# encrypt sid with k
enc_sid_to_c = fernetKfromC.encrypt(sID.encode())

# info for C
info_for_c = response + ',' + sID + "," + str(amount) + "," \
             + client_number

# hash info for c
hash_info_for_c = int.from_bytes(sha512(info_for_c.encode()).digest(), byteorder='big')

# generate info signature
keyPair_info = RSA.generate(bits=1024)
info_signature = pow(hash_info_for_c, keyPair_info.d, keyPair_info.n)

# encrypt signature
enc_sign_for_c = fernetKfromC.encrypt(str(info_signature).encode())

# encrypt k from c with kc
enc_k_from_c = fernetKC.encrypt(K)

# send encrypted response to C
c.sendall(enc_response)
data = c.recv(1024)

# send encrypted sid to C
c.sendall(enc_sid_to_c)
data = c.recv(1024)

# send encrypted signature to C
c.sendall(enc_sign_for_c)
data = c.recv(1024)

# send encrypted k to c
c.sendall(enc_k_from_c)
data = c.recv(1024)
keypair_e = str(keyPair_info.e)

# send keypairPI_e to C
c.sendall(keypair_e.encode())
data = c.recv(1024)
keypair_n = str(keyPair_info.n)

# send keypairPI_e to C
c.sendall(keypair_n.encode())
data = c.recv(1024)

c.close()
m.close()
sys.exit()
