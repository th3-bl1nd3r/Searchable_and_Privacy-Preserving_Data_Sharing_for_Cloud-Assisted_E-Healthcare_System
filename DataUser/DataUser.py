
import time
from texttable import Texttable
from middlewares.ModifiedPaillier import oppoE
from middlewares.Conversion import prepare_keyword
from middlewares.AES_CBC_256 import SE
from middlewares.HMAC_SHA_256 import hmac_sha256
from base64 import b64decode
import json
import socket
import ssl
from gmpy2 import *
from traceback import print_exception
import threading

vitalsigns = ["age", "gender", "tot_bilirubin", "direct_bilirubin", "alkphos",
              "sgpt", "sgot", "tot_proteins", "albumin", "ag_ratio", "is_patient"]


def recvuntilendl(client):
    res = b''
    while (True):
        ch = client.recv(1)
        if not ch:
            break
        if (ch == b'\n'):
            break
        res += ch
    return res


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname='trust-authority.duckdns.org')
s.connect(('trust-authority.duckdns.org', 2810))
s.sendall(b"DataUser\n")
data = recvuntilendl(s).decode().replace(',', '\n')
exec(data)
s.close()
pk = {'n': mpz(n), 'h': mpz(h), 'g': mpz(g)}

key = bytes.fromhex(kse)
kse, iv = key[0:32], key[32:]


def decode_result(result):
    res = []
    # print(result)
    for r in result:
        id = r[0]
        Cv = r[1]
        fq = SE(iv, kse).Dec(b64decode(Cv))
        # print(fq)
        Mac = fq[:32]
        f = fq[32:]
        Macq = hmac_sha256(k, f)
        if Macq != Mac:
            continue
        res.append([id] + [fi for fi in f.decode().split(',')])
    res.sort()
    return res


def multi_keyword_search(k: list):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(s, server_hostname='cloudsbshd.duckdns.org')
    s.connect(('cloudsbshd.duckdns.org', 2809))
    query = []
    for ki in k:
        query.append(oppoE(pk, prepare_keyword(
            vitalsigns[ki[0]].encode()) + prepare_keyword(ki[1])))
    query = json.dumps(query)
    s.sendall(b'DataUser\n')
    s.sendall((query+'\n').encode())
    result = json.loads(json.loads(recvuntilendl(s).decode()))
    s.close()
    return decode_result(result)


def keyword_range_search(index, k1, k2):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(s, server_hostname='cloudsbshd.duckdns.org')
    s.connect(('cloudsbshd.duckdns.org', 2809))

    r = abs(prepare_keyword(k2) - prepare_keyword(k1))
    Esw = oppoE(pk, prepare_keyword(
        vitalsigns[index].encode()) + prepare_keyword(k1))
    query = json.dumps({'Esw': Esw, 'r': r})
    s.sendall(b'DataUser\n')
    s.sendall((query+'\n').encode())
    result = json.loads(json.loads(recvuntilendl(s).decode()))
    s.close()
    return decode_result(result)


def print_header():
    print("================================================")
    print("        Welcome to Health Data Searching        ")
    print("================================================")
    print()


def print_menu():
    print("---------------- Menu Options ------------------")
    print("1. Keyword Range Seach.")
    print("2. Multi-keyword search.")
    print("3. Exit")
    print("------------------------------------------------")
    print()


def process_keyword_range_search():
    try:
        print("------------ Keyword Range Search --------------")
        print("| " + " | ".join(v for v in vitalsigns) + " |")
        v = input("Choose a vitalsigns: ")
        index = vitalsigns.index(v)
        k1 = input(
            "Start of the range you want to search (value must be 'Male', 'Female' or integer): ")
        k2 = input(
            "End of the range you want to search (value must be 'Male', 'Female' or integer): ")
        start = time.time()
        result = keyword_range_search(index, k1.encode(), k2.encode())
        searchtime = time.time() - start
        print("Time: " + str(searchtime))
        print_result(result)
    except Exception as e:
        # print("Error!")
        print_exception(e)
        return


def process_multi_keyword_search():
    try:
        print("------------ Multi-keyword Search --------------")
        n = int(input("How many keywords do you want to search: "))
        query = []
        for i in range(n):
            print("| " + " | ".join(v for v in vitalsigns) + " |")
            v = input("Choose a vitalsigns: ")
            index = vitalsigns.index(v)
            k = input(
                "Value you want to search (value must be 'Male', 'Female' or integer): ")
            query.append([index, k.encode()])
        start = time.time()
        result = multi_keyword_search(query)
        searchtime = time.time() - start
        print("Time: " + str(searchtime))
        print_result(result)
    except Exception as e:
        print("Error!")
        print_exception(e)
        return


def print_result(result):
    print(f"About {len(result)} results.")
    print("------------------------------------------------------------ Result -------------------------------------------------------------")
    t = Texttable(max_width=400)
    headers = ["id"] + vitalsigns
    result.insert(0, headers)
    t.add_rows(result)
    print(t.draw())
    print("---------------------------------------------------------------------------------------------------------------------------------")
    print()


def print_goodbye():
    print("------------------------------------------------")
    print("          Thank you for using My Program        ")
    print("------------------------------------------------")
    print()


def main():
    print_header()
    # process_keyword_range_search()
    # process_multi_keyword_search()
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        if choice == "1":
            process_keyword_range_search()
        elif choice == "2":
            process_multi_keyword_search()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")
            print()
    print_goodbye()


if __name__ == "__main__":
    main()
