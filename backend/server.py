import asyncio
import time
import websockets
import json
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import hashlib


def LOG_DEBUG(msg):
    msg = "[debug]:" + msg
    # print(msg)


def LOG(msg):
    msg = "[i]:" + msg
    print(msg)


def LOG_VERBOSE(msg):
    msg = "[v]:" + msg
    print(msg)


HEARTBEAT_INTERVAL = 3  # seconds


class Server:
    def __init__(self):
        self.channels = {}
        self.last_package = {}

    def hash_public_key(self, public_key):
        der = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashlib.sha256(der).hexdigest()
        print(digest)
        return digest

    async def handler(self, websocket, path):
        client_info = {'websocket': websocket, 'public_key': None, 'public_key_hash': None}
        self.last_package[websocket] = time.time()
        try:
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=HEARTBEAT_INTERVAL)
                except asyncio.TimeoutError:
                    if time.time() - self.last_package[websocket] > HEARTBEAT_INTERVAL * 2:
                        LOG(f'No heartbeat, client assumed disconnected.')
                        break
                    await websocket.send(json.dumps({'action': 'heartbeat'}))
                    continue

                data = json.loads(message)
                self.last_package[websocket] = time.time()
                if 'action' in data:
                    if data['action'] == 'heartbeat':
                        self.last_package[websocket] = time.time()
                    elif data['action'] == 'join':
                        LOG(f'{data}')
                        self.join_channel(data, client_info)
                    elif data['action'] == 'send_key':
                        LOG(f'{data}')
                        await self.send_key(data, client_info)
                    elif data['action'] == 'send_message':
                        LOG(f'{data}')
                        await self.send_message(data, client_info)
        except websockets.exceptions.ConnectionClosedError as e:
            LOG(f'WebSocket connection closed: {e.code} - {e.reason}')
        except Exception as e:
            LOG(f'可能有人强制关闭了。{e}')
        finally:
            LOG(f'self.handle_client_disconnect(client_info)')
            self.handle_client_disconnect(client_info)

    async def send_public_keys(self, channel_id, channel_id_signature):
        clients = self.channels[channel_id]
        for client in clients:
            other_clients = [c for c in clients if c != client]
            for other_client in other_clients:
                other_public_key = other_client['public_key'].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                await client['websocket'].send(json.dumps({
                    'action': 'receive_public_key',
                    'public_key': other_public_key,
                    'public_key_hash': other_client.get('public_key_hash'),
                    # 这里加一个字段，hmac(channel_id, 自己公钥签名)。
                    # 接收的时候如果这个值不对，说明这个人不知道channel_id的真实值。
                    # 服务器能知道别人用的这个签名，但是那是别人的公钥，自己的公钥的签名无从得知，那signature字段就是非法的，还是过不去校验。
                    # 这里要从全局列表取。
                    'channel_id_signature': other_client.get('channel_id_signature'),
                }))
        # 让新加入这个人生成密钥
        # TODO:随机选一个人生成密钥
        last_client = clients[-1]['websocket']
        await last_client.send(json.dumps({'action': 'generate_aes_key'}))

    def print_channels(self):
        for key, value in self.channels.items():
            LOG_VERBOSE(f'频道{key}共有{len(value)}个用户，用户hash如下')
            for i in value:
                LOG_VERBOSE(i['public_key_hash'])

    def join_channel(self, data, client_info):
        self.print_channels()

        channel_id = data['channel_id']
        channel_id_signature = data.get('channel_id_signature', None)
        public_key = serialization.load_pem_public_key(data['public_key'].encode())
        public_key_hash = self.hash_public_key(public_key)
        client_info['public_key'] = public_key
        client_info['public_key_hash'] = public_key_hash
        client_info['channel_id_signature'] = channel_id_signature
        LOG_VERBOSE(f'当前用户{public_key_hash}想加入{channel_id}。')
        if channel_id not in self.channels:
            self.channels[channel_id] = [client_info]
        else:
            self.channels[channel_id].append(client_info)
            asyncio.ensure_future(self.send_public_keys(channel_id, channel_id_signature))

    async def send_key(self, data, client_info):
        channel_id = data['channel_id']
        encrypted_key = data['encrypted_key']
        public_key_hash = data['public_key_hash']
        sender_public_key_hash = data['sender_public_key_hash']
        nonce = data['nonce']
        timestamp = data['timestamp']
        signature = data['signature']
        channel_id_signature = data.get('channel_id_signature', None)  # 没有就是None
        for client in self.channels[channel_id]:
            if client['public_key_hash'] == public_key_hash:
                await client['websocket'].send(json.dumps({
                    'action': 'receive_key',
                    'encrypted_key': encrypted_key,
                    'public_key_hash': public_key_hash,
                    'sender_public_key_hash': sender_public_key_hash,
                    'nonce': nonce,
                    'timestamp': timestamp,
                    'signature': signature,

                    # 这里加一个字段，hmac(channel_id, 自己公钥签名)。
                    # 接收的时候如果这个值不对，说明这个人不知道channel_id的真实值。
                    # 服务器能知道别人用的这个签名，但是那是别人的公钥，自己的公钥的签名无从得知，那signature字段就是非法的，还是过不去校验。
                    'channel_id_signature': channel_id_signature,
                }))

    async def send_message(self, data, client_info):
        channel_id = data['channel_id']
        encrypted_message = data['encrypted_message']
        for client in self.channels[channel_id]:
            if client['websocket'] != client_info['websocket']:
                await client['websocket'].send(
                    json.dumps({
                        'action': 'receive_message',
                        'encrypted_message': encrypted_message,
                        'public_key_hash': client_info['public_key_hash']
                    }))

    def handle_client_disconnect(self, client_info):
        # 查找客户端所在的频道
        for channel_id, clients in self.channels.items():
            if client_info in clients:
                clients.remove(client_info)
                # 通知频道中的其他成员有人退出
                disconnect_message = json.dumps({
                    'action': 'member_left',
                    'public_key_hash': client_info['public_key_hash']
                })
                # 发送退出通知给其他成员
                for client in clients:
                    asyncio.ensure_future(client['websocket'].send(disconnect_message))
                # 如果频道中还有其他客户端，重新生成并分发AES密钥
                if clients:
                    asyncio.ensure_future(self.send_public_keys(channel_id))
                break


# 创建SSL上下文
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('chat.yuchu.space.pem', 'chat.yuchu.space.key')

server = Server()
start_server = websockets.serve(server.handler, "0.0.0.0", 8765, ssl=ssl_context, max_size=1024 * 1024 * 100)  # 10MB

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
