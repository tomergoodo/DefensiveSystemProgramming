import socket
import selectors
import struct
import uuid
import time
import sqlite3
from enum import Enum
from datetime import datetime

HOST = ''


class Server:
    def __init__(self, host, port):
        self.buffer_size = 0xFFFF  # 64KB
        self._version = 1
        self._protocol = Protocol()
        self._sql_conn = sqlite3.connect("server.db")
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.bind((host, port))
            self._socket.setblocking(False)
        except OSError:
            print("OSError: error creating/binding socket")
            exit(1)

        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ, self._handle_accept)

        self._current_peers = {}
        self._clients = {}
        self._create_tables()
        self._load_clients()

    def __del__(self):
        self._socket.close()
        self._sql_conn.close()

    def start(self):
        self._socket.listen(256)
        last_report_time = time.time()

        while True:
            events = self._selector.select(timeout=0.2)  # 200ms

            for key, mask in events:
                handler = key.data
                handler(key.fileobj)

            cur_time = time.time()
            if cur_time - last_report_time > 1:
                print('Running report...')
                print(f'Number of active peers = {len(self._current_peers)}')
                last_report_time = cur_time

    def _handle_accept(self, sock):
        conn, addr = self._socket.accept()
        print(f'accepted connection from {addr}')
        conn.setblocking(False)

        self._current_peers[conn.fileno()] = conn.getpeername()

        self._selector.register(conn, selectors.EVENT_READ, self._handle_recv)

    def _close_connection(self, conn):
        if conn.fileno() in self._current_peers:
            peer_name = self._current_peers[conn.fileno()]
            print('closing connection to {0}'.format(peer_name))
            del self._current_peers[conn.fileno()]
            self._selector.unregister(conn)
            conn.close()

    def _handle_recv(self, conn: socket.socket):
        header = self._recv(conn, self._protocol.request_header_size)
        if not header:
            return
        request = Request(header, self._protocol)
        payload = self._recv(conn, min(request.payload_size_left, self.buffer_size))
        request.payload_size_left = 0
        request.add_payload(payload)
        self._handle_request(conn, request)

    def _handle_request(self, conn, request):
        if request.code == self._protocol.RequestCodes.REGISTER.value:
            ret = self._register(request)
            if ret:
                self._send_answer(conn, self._protocol.AnswerCodes.REGISTER, request.uid)
            else:
                self._send_answer(conn, self._protocol.AnswerCodes.FAILURE, None)
        else:
            if request.uid not in self._clients:
                self._send_answer(conn, self._protocol.AnswerCodes.FAILURE, None)
            else:
                client = self._clients[request.uid]
                client.set_last_seen()
                if request.code == self._protocol.RequestCodes.CLIENT_LIST.value:
                    payload = self._client_list(request.uid)
                    self._send_answer(conn, self._protocol.AnswerCodes.CLIENT_LIST, payload)
                elif request.code == self._protocol.RequestCodes.PUB_KEY.value:
                    payload = self._pub_key(request)
                    if payload is not None:
                        self._send_answer(conn, self._protocol.AnswerCodes.PUB_KEY, payload)
                    else:
                        self._send_answer(conn, self._protocol.AnswerCodes.FAILURE, None)
                elif request.code == self._protocol.RequestCodes.SEND_MESSAGE.value:
                    payload = self._store_message(conn, request)
                    self._send_answer(conn, self._protocol.AnswerCodes.SEND_MESSAGE, payload)
                elif request.code == self._protocol.RequestCodes.GET_MESSAGE.value:
                    payload = self._get_messages(client)
                    self._send_answer(conn, self._protocol.AnswerCodes.GET_MESSAGE, payload)
                else:
                    self._send_answer(conn, self._protocol.AnswerCodes.FAILURE, None)

    def _recv(self, conn, size):
        if size == 0:
            return b''
        data = b''
        try:
            data = conn.recv(size)
            if data:
                peer_name = conn.getpeername()
                print('got data of size {} from {}: {!r}'.format(len(data), peer_name, data))
            else:
                self._close_connection(conn)
        except ConnectionResetError:
            self._close_connection(conn)
        except BlockingIOError:
            self._send_answer(conn, self._protocol.AnswerCodes.FAILURE, None)
            self._close_connection(conn)
        except OSError:
            self._close_connection(conn)
        return data

    def _register(self, request):
        client = Client(uuid.uuid4(), *Client.parse_client(request.payload))
        for c in self._clients.values():
            if client.name == c.name:
                return False
        request.uid = client.uid.bytes
        self._clients[client.uid.bytes] = client
        self._store_register_db(client)

        return True

    def _client_list(self, uid):
        payload = bytearray(0)
        for client in self._clients.values():
            if client.uid.bytes != uid:
                payload += client.uid.bytes + client.name
        return payload

    def _pub_key(self, request):
        uid = request.payload[:self._protocol.uid_size]
        return uid + self._clients[uid].pub_key

    def _store_message(self, conn, request):
        message = Message(None, *Message.parse_message(request.payload, self._protocol), request.uid)
        while message.content_size_left > 0:
            payload = self._recv(conn, min(message.content_size_left, self.buffer_size))
            request.add_payload(payload)
            request.payload_size_left -= len(payload)
            message.add_content(payload)
            message.content_size_left -= len(payload)
        self._store_message_db(message)
        return message.to_client + struct.Struct("<I").pack(message.index)

    def _get_messages(self, client):
        payload = bytearray(0)
        messages = self._fetch_messages(client.uid.bytes)
        for msg in messages:
            payload += msg.from_client + struct.Struct("<LBL").pack(msg.index, msg.type,
                                                                    msg.content_size) + msg.content

        return payload

    def _send_answer(self, conn, code, payload):
        header = struct.Struct("<BHL").pack(self._version, code.value, 0 if payload is None else len(payload))
        try:
            if payload is not None:
                conn.sendall(header + payload)
            else:
                conn.sendall(header)
        except OSError:
            print("OSError: error sending packet")

    def _store_register_db(self, client):
        cur = self._sql_conn.cursor()
        cur.execute("""INSERT INTO clients VALUES (?,?,?,?);""",
                    [client.uid.bytes, client.name, client.pub_key, client.last_seen])
        self._sql_conn.commit()

    def _load_clients(self):
        cur = self._sql_conn.cursor()
        cur.execute("SELECT * FROM clients")
        clients = cur.fetchall()
        for c in clients:
            client = Client(uuid.UUID(bytes=c[0]), c[1], c[2])  # id, name, key
            self._clients[client.uid.bytes] = client

    def _update_client_last_seen(self, client):
        cur = self._sql_conn.cursor()
        cur.execute("UPDATE clients SET LastSeen=? WHERE ID=?", [client.last_seen, client.uid.bytes])

    def _store_message_db(self, message):
        cur = self._sql_conn.cursor()
        cur.execute("""INSERT INTO messages VALUES (?,?,?,?,?);""",
                    [message.index, message.to_client, message.from_client, message.type,
                     message.content])
        self._sql_conn.commit()

    def _fetch_messages(self, to_client):
        cur = self._sql_conn.cursor()
        cur.execute("SELECT * FROM messages WHERE ToClient=?", [to_client])
        raw_messages = cur.fetchall()
        messages = []
        for raw_message in raw_messages:
            id = raw_message[0]
            to_client = raw_message[1]
            from_client = raw_message[2]
            type = raw_message[3]
            content = raw_message[4]
            messages.append(Message(id, to_client, type, len(content), content, from_client))
        cur.execute("DELETE FROM messages WHERE ToClient=?", [to_client])
        return messages

    def _create_tables(self):
        cur = self._sql_conn.cursor()
        cur.executescript(f"""
                CREATE TABLE IF NOT EXISTS clients(
                ID varchar({self._protocol.uid_size}) NOT NULL PRIMARY KEY,
                Name varchar({Client.name_size}),
                PublicKey varchar({Client.pub_key_size}),
                LastSeen TEXT);
                """)
        cur.executescript(f"""
                CREATE TABLE IF NOT EXISTS messages(
                ID INTEGER4,
                ToClient varchar({self._protocol.uid_size}),
                FromClient varchar({self._protocol.uid_size}),
                Type INTEGER1,
                content BLOB);
                """)


class Protocol:
    def __init__(self):
        self.version = 1
        self.uid_size = 16
        self.pub_key_size = 160
        self.request_header = struct.Struct("<" + "x" * self.uid_size + "BBL")
        self.request_header_size = struct.calcsize("<" + "x" * self.uid_size + "BBL")
        self.message_header = struct.Struct("<" + "x" * self.uid_size + "BL")
        self.message_header_size = struct.calcsize("<" + "x" * self.uid_size + "BL")

    class RequestCodes(Enum):
        REGISTER = 100
        CLIENT_LIST = 101
        PUB_KEY = 102
        SEND_MESSAGE = 103
        GET_MESSAGE = 104

    class AnswerCodes(Enum):
        REGISTER = 1000
        CLIENT_LIST = 1001
        PUB_KEY = 1002
        SEND_MESSAGE = 1003
        GET_MESSAGE = 1004
        FAILURE = 9000


class Request:
    def __init__(self, header, protocol):
        try:
            header_info = protocol.request_header.unpack(header[:protocol.request_header_size])
        except struct.error:
            print("struct.unpack failed")
            header_info = (protocol.version, 0, 0)  # default values
        self.uid = header[:protocol.uid_size]
        self.version = header_info[0]
        self.code = header_info[1]
        self.payload_size = header_info[2]
        self.payload_size_left = self.payload_size - (len(header) - protocol.request_header_size)
        self.payload = header[protocol.request_header_size:]

    def add_payload(self, payload):
        self.payload += payload


class Message:
    counter = 0

    def __init__(self, id, to_client, type, content_size, content, from_client):
        if id is None:
            self.index = Message.counter
            Message.counter += 1
        else:
            self.index = id
        self.to_client = to_client
        self.type = type
        self.content_size = content_size
        self.content = content
        self.content_size_left = content_size - len(content)

        self.from_client = from_client

    @staticmethod
    def parse_message(payload, protocol):
        try:
            header = protocol.message_header.unpack(payload[:protocol.message_header_size])
        except struct.error:
            print("struct.unpack failed")
            header = (0, 0)  # default values
        to_client = payload[:protocol.uid_size]
        type = header[0]
        content_size = header[1]
        content = payload[protocol.message_header_size:]
        return to_client, type, content_size, content

    def add_content(self, content):
        self.content += content


class Client:
    name_size = 255
    pub_key_size = 160

    def __init__(self, uid, name, public_key):
        self.uid = uid
        self.name = name
        self.pub_key = public_key

        now = datetime.now()
        self.last_seen = now.strftime("%d/%m/%Y %H:%M:%S")

    @staticmethod
    def parse_client(payload):
        name = payload[:Client.name_size]
        pub_key = payload[Client.name_size:Client.name_size + Client.pub_key_size]
        return name, pub_key

    def set_last_seen(self):
        now = datetime.now()
        self.last_seen = now.strftime("%d/%m/%Y %H:%M:%S")


def load_port(file):
    with open(file, "r") as f:
        while True:
            try:
                port = int(f.read())
                break
            except ValueError:
                print("port should be an integer between 0 - 65,535")
            except FileNotFoundError:
                print(f"file {file} not found")
                exit(1)
    return port


def main():
    print('Starting')
    PORT = load_port("port.info")
    server = Server(host=HOST, port=PORT)
    server.start()


if __name__ == '__main__':
    main()
