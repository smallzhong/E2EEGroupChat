const uri = 'wss://chat.yuchu.space:8765';
let websocket = null;
let privateKey = null;
let publicKey = null;
let aesKey = null;
let otherPublicKeys = {};
let g_channel_id = null;
let reconnectInterval = 5000;  // 重连间隔时间，5秒

forge.util.encodeUtf8 = function (str) {
    return unescape(encodeURIComponent(str));
};

forge.util.decodeUtf8 = function (bytes) {
    return decodeURIComponent(escape(bytes));
};

function appendMessageToChatBox(message) {
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const messageText = document.createTextNode(`${message}`);
    messageElem.appendChild(messageText);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

document.addEventListener('DOMContentLoaded', function () {
    const queryString = window.location.search.substring(1); // 去掉前面的 '?'
    const channelId = queryString ? queryString : null; // 如果有查询参数，则取其值，否则返回 null
    console.log("channelid = " + channelId);

    if (channelId) {
        document.getElementById('status-message').innerText = '正在生成 RSA 密钥...';
        privateKey = forge.pki.rsa.generateKeyPair(2048).privateKey;
        publicKey = forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e);
        g_channel_id = channelId;
        connectWebSocket();
    } else {
        document.getElementById('status-message').innerText = '无效的频道 ID';
    }

    // 监听按 Enter 键发送消息和 Shift+Enter 换行
    document.getElementById('input-message').addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();  // 阻止默认的 Enter 行为
            sendMessage();
        }
    });
});

function connectWebSocket() {
    websocket = new WebSocket(uri);
    websocket.onopen = function () {
        console.log("WebSocket 已连接");
        joinChannel(g_channel_id);
    };
    websocket.onmessage = function (event) {
        handleIncomingMessage(event.data);
    };
    websocket.onerror = function (error) {
        console.error('WebSocket Error: ' + error);
    };
    websocket.onclose = function (event) {
        console.log('WebSocket closed, attempting to reconnect...', event.reason);
        setTimeout(connectWebSocket, reconnectInterval);
    };
}

function joinChannel(channelId) {
    const publicKeyPem = forge.pki.publicKeyToPem(publicKey);
    const message = JSON.stringify({ action: 'join', channel_id: channelId, public_key: publicKeyPem });
    websocket.send(message);
    document.getElementById('status-message').innerText = '加入成功';
    document.getElementById('input-message').disabled = false; // 启用消息输入框
    updateUsersList(); // 更新用户列表
}

function sendMessage() {
    const input = document.getElementById('input-message');
    const message = input.value.trim();
    input.value = '';  // 清空输入框
    if (message !== '') {
        const encryptedMessage = encryptMessage(message);
        websocket.send(JSON.stringify({
            action: 'send_message',
            channel_id: g_channel_id,
            encrypted_message: encryptedMessage
        }));
        // 展示自己的消息
        appendMessageToChatBox(`我: ${message}`);
    }
}

function encryptMessage(message) {
    if (!aesKey) {
        console.error('AES key not set');
        return '';
    }
    const cipher = forge.cipher.createCipher('AES-CTR', aesKey);
    const iv = forge.random.getBytesSync(16); // 确保16字节IV
    cipher.start({ iv: iv });

    // 转换消息为 UTF-8 编码
    const utf8Message = forge.util.encodeUtf8(message);
    cipher.update(forge.util.createBuffer(utf8Message));
    if (!cipher.finish()) {
        console.error('Encryption failed');
        return '';
    }
    const encrypted = cipher.output.getBytes();

    const md = forge.md.sha256.create();
    md.update(utf8Message, 'utf8'); // 使用 UTF-8 编码的消息进行摘要计算
    const digest = md.digest().bytes();
    console.log(`SHA256 digest for message "${message}": ${forge.util.encode64(digest)}`);

    const signature = privateKey.sign(md);
    console.log(`Signature for message "${message}": ${forge.util.encode64(signature)}`);

    return JSON.stringify({
        nonce: forge.util.encode64(iv),
        ciphertext: forge.util.encode64(encrypted),
        signature: forge.util.encode64(signature)
    });
}

function handleIncomingMessage(data) {
    const messageData = JSON.parse(data);
    console.log(messageData);
    switch (messageData.action) {
        case 'heartbeat':
            sendHeartbeat();
            break;
        case 'receive_message':
            // 确保传递 public_key_hash
            displayMessage(messageData.encrypted_message, messageData.public_key_hash);
            break;
        case 'receive_public_key':
            const publicKey = forge.pki.publicKeyFromPem(messageData.public_key);
            if (!otherPublicKeys.hasOwnProperty(messageData.public_key_hash)) {
                otherPublicKeys[messageData.public_key_hash] = publicKey;
                handleNewMemberJoin(messageData.public_key_hash);
            }
            break;
        case 'generate_aes_key':
            generateAndSendAESKey();
            break;
        case 'receive_key':
            aesKey = privateKey.decrypt(forge.util.decode64(messageData.encrypted_key), 'RSA-OAEP', {
                md: forge.md.sha256.create(),
                mgf1: {
                    md: forge.md.sha256.create()
                }
            });
            break;
        case 'member_left':
            handleMemberLeft(messageData.public_key_hash);
            break;
        default:
            console.warn('Unknown action:', messageData.action);
    }
}

function sendHeartbeat() {
    const message = JSON.stringify({ action: 'heartbeat' });
    websocket.send(message);
}

function displayMessage(encryptedMessage, publicKeyHash) {
    const messageData = JSON.parse(encryptedMessage);
    const iv = forge.util.decode64(messageData.nonce);
    const ciphertext = forge.util.decode64(messageData.ciphertext);
    const signature = messageData.signature;
    const decipher = forge.cipher.createDecipher('AES-CTR', aesKey);
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(ciphertext));
    if (!decipher.finish()) {
        console.error('Decryption failed');
        return;
    }
    const utf8MessageBytes = decipher.output.getBytes();
    const utf8Message = forge.util.decodeUtf8(utf8MessageBytes);

    if (verifySignature(publicKeyHash, utf8MessageBytes, signature)) {
        appendMessageToChatBox(`${publicKeyHash}: ${utf8Message}`);
    } else {
        console.error('Signature verification failed');
    }
}

function verifySignature(publicKeyHash, utf8MessageBytes, signature) {
    const publicKey = otherPublicKeys[publicKeyHash];
    if (!publicKey) {
        console.error('Public key not found for hash:', publicKeyHash);
        return false;
    }
    const md = forge.md.sha256.create();
    md.update(utf8MessageBytes, 'utf8'); // 使用 UTF-8 编码的字节数组进行摘要计算
    try {
        return publicKey.verify(md.digest().bytes(), forge.util.decode64(signature));
    } catch (e) {
        console.error('Signature verification failed:', e);
        return false;
    }
}

function generateAndSendAESKey() {
    aesKey = forge.random.getBytesSync(32);
    for (let hash in otherPublicKeys) {
        const publicKey = otherPublicKeys[hash];
        const encryptedKey = publicKey.encrypt(aesKey, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: {
                md: forge.md.sha256.create()
            }
        });
        websocket.send(JSON.stringify({
            action: 'send_key',
            channel_id: g_channel_id,
            encrypted_key: forge.util.encode64(encryptedKey),
            public_key_hash: hash
        }));
    }
}

function handleMemberLeft(publicKeyHash) {
    delete otherPublicKeys[publicKeyHash];
    updateUsersList(); // 更新用户列表
    appendMessageToChatBox(`用户 ${publicKeyHash} 已离开。`);
}

function handleNewMemberJoin(publicKeyHash) {
    updateUsersList(); // 更新用户列表
    appendMessageToChatBox(`新成员加入: ${publicKeyHash}`);
}

function updateUsersList() {
    const usersList = document.getElementById('users-list');
    const totalUsers = Object.keys(otherPublicKeys).length + 1; // +1 包括自己
    let usersInfo = `在线用户: ${totalUsers}<br>我: 自己<br>`;
    for (let publicKeyHash in otherPublicKeys) {
        usersInfo += `${publicKeyHash}: 其他用户<br>`;
    }
    usersList.innerHTML = usersInfo;
    document.getElementById('status-message').innerText = `当前频道：${g_channel_id}（在线用户: ${totalUsers}）`;
}
