import ssl
import socket
from traceback import print_exception
import threading
from middlewares.ModifiedPaillier import _mul_, oppoE, DEp1, DEp2
from middlewares.HMAC_SHA_256 import hmac_sha256, int_to_bytes
from middlewares.VariantBloomFilter import *
from pybloom import BloomFilter
from base64 import b64decode, b64encode
import json
import time
from gmpy2 import *
VBF = BloomFilter(capacity=10000)

TBL = {}
EncodedFile = {}
label = 1


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


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        context_server = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH)
        context_server.load_cert_chain(
            certfile='./cloudsashd.duckdns.org/certificate.crt', keyfile='./cloudsashd.duckdns.org/ec-private-key.pem')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.s_sock = context_server.wrap_socket(self.sock, server_side=True)

    def listen(self):
        while True:
            client, address = self.s_sock.accept()
            client.settimeout(60)
            threading.Thread(target=self.listenToClient,
                             args=(client, address)).start()

    def listenToClient(self, client, address):
        try:
            while True:
                data = recvuntilendl(client)
                # print(data)
                if data:
                    # Set the response to echo back the recieved data
                    # print(data)
                    if (data.decode() == 'IOTgateway'):
                        data = recvuntilendl(client)
                        data = json.loads(data.decode())
                        # print(data)
                        Cv = b64decode(data['Cv'])
                        Cw = b64decode(data['Cw']).split(b', ')
                        Ew = [json.loads(wi.replace(b". ", b", ").decode())
                              for wi in b64decode(data['Ew']).replace(b", ", b". ").split(b',')]
                        id = data['id']
                        mac = b64decode(data['mac'])
                        macq = hmac_sha256(t0, Cv + b', '.join(Cw) +
                                           b','.join(json.dumps(wi).encode() for wi in Ew))
                        assert (mac == macq)
                        # pass
                        # print(TBL)

                        for i in range(len(Cw)):
                            if (VBFVerify(VBF, Cw[i]) == 1):
                                TBL[Cw[i]]['fileid'].append(id)
                            else:
                                TBL[Cw[i]] = {}
                                TBL[Cw[i]]['keyword'] = Ew[i]
                                TBL[Cw[i]]['fileid'] = [id]
                                VBFAdd(VBF, Cw[i])
                        # print(TBL)
                        EncodedFile[id] = b64encode(Cv).decode()
                        print(len(TBL.keys()))
                    elif data.decode() == 'CloudServerSB':
                        query = recvuntilendl(client)
                        query = json.loads(query.decode())
                        fileIDresults = set()
                        cnt = 1
                        if type(query) == type({}):
                            for Et in query['a']:
                                for key in TBL.keys():
                                    D = _mul_(
                                        pk, TBL[key]['keyword'], query['Esw'])
                                    D = _mul_(pk, D, Et)
                                    Dq = DEp1(pk, skp1, D)
                                    client.sendall(
                                        (json.dumps(Dq) + '\n').encode())
                                    res = json.loads(recvuntilendl(
                                        client).decode())['res']
                                    if (res == 1):
                                        fileIDresults.update(
                                            TBL[key]['fileid'])
                                    print(cnt)
                                    cnt += 1
                            client.sendall(b'End\n')
                        else:
                            # print(TBL)
                            # start = time.time()
                            for Esw in query:
                                res_tmp = set()
                                for key in TBL.keys():
                                    D = _mul_(
                                        pk, TBL[key]['keyword'], Esw)
                                    Dq = DEp1(pk, skp1, D)
                                    client.sendall(
                                        (json.dumps(Dq) + '\n').encode())
                                    res = json.loads(recvuntilendl(
                                        client).decode())['res']
                                    if (res == 1):
                                        res_tmp.update(
                                            TBL[key]['fileid'])

                                    print(cnt)
                                    cnt += 1
                                if Esw == query[0]:
                                    fileIDresults.update(res_tmp)
                                else:
                                    fileIDresults.intersection_update(
                                        res_tmp)
                            client.sendall(b'End\n')
                            # print(time.time() - start)

                        result = []
                        for id in fileIDresults:
                            result.append([id, EncodedFile[id]])
                        client.sendall(
                            (json.dumps(result) + '\n').encode())
                    elif data.decode() == 'TrustAuthority':
                        data = recvuntilendl(
                            client).decode().replace(',', '\n')

                        exec(data, globals(), globals())

                        exec(
                            "pk = {'n': mpz(n), 'h': mpz(h), 'g': mpz(g)}", globals(), globals())
                        # print(pk)

                else:
                    raise Exception('Client disconnected')
        except Exception as e:
            print_exception(e)
            print('Client disconnected')
            client.close()


if __name__ == "__main__":
    # port = int(input("Port? "))
    while True:
        ThreadedServer('0.0.0.0', 2808).listen()
