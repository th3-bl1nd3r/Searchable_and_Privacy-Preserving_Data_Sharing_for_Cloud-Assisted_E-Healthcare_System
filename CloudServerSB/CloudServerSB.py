import ssl
import json
import socket
import threading
from traceback import print_exception
from middlewares.Conversion import *
from middlewares.ModifiedPaillier import *
from gmpy2 import *


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
            certfile='./cloudsbshd.duckdns.org/certificate.crt', keyfile='./cloudsbshd.duckdns.org/ec-private-key.pem')

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
                    if (data.decode() == 'DataUser'):
                        data = recvuntilendl(client).decode()
                        data = json.loads(data)
                        context_client = ssl.create_default_context(
                            ssl.Purpose.SERVER_AUTH)
                        sa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sa = context_client.wrap_socket(
                            sa, server_hostname='cloudsashd.duckdns.org')
                        # Connect to SA
                        sa.connect(('cloudsashd.duckdns.org', 2808))

                        if type(data) == type({}):
                            a = []
                            r = data['r']
                            Esw = data['Esw']
                            for i in range(r + 1):
                                a.append(oppoE(pk, prepare_keyword(i)))
                            query = {'Esw': Esw, 'a': a}
                            # print(query)
                        else:
                            query = data
                            pass

                        sa.sendall(b'CloudServerSB\n')
                        sa.sendall((json.dumps(query) + '\n').encode())
                        result = []
                        while True:
                            Dq = recvuntilendl(sa)
                            if Dq == b'End':
                                break
                            Dq = json.loads(Dq.decode())
                            Dqq = DEp2(pk, skp2, Dq)
                            if Dqq == 0:
                                msg = {'res': 1}
                            else:
                                msg = {'res': 0}
                            sa.sendall((json.dumps(msg) + '\n').encode())
                            # res = json.loads(recvuntilendl(sa).decode())
                            # result.append(res)
                        result = recvuntilendl(sa).decode()
                        client.sendall(
                            (json.dumps(result) + '\n').encode())
                        # print(result)
                        sa.close()
                    elif data.decode() == 'TrustAuthority':
                        data = recvuntilendl(
                            client).decode().replace(',', '\n')

                        exec(data, globals(), globals())

                        # pk = {'n': mpz(n), 'h': mpz(h), 'g': mpz(g)}
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
        ThreadedServer('0.0.0.0', 2809).listen()

# data =
# data = json.loads(data)
# if 'r' in data.keys():
#     a = []
#     r = data['r']
#     Esw = data['Esw']
#     for i in range(r + 1):
#         a.append(oppoE(pk, prepare_keyword(i)))
#     query = {'Esw': Esw, 'a': a}
#     print(json.dumps(query))
