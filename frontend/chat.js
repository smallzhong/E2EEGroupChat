const g_uri = 'wss://chat.yuchu.space:8765';
const nonceLifeTime = 300000; // nonce的生命是5分钟
const nonceCleanUpInterval = 60000; // 每隔1分钟清理一次nonce
let g_websocket = null;
let g_myPrivateKey = null;
let g_myPublicKey = null;
let g_aesKey = null;
let g_otherPublicKeys = {};
let g_userNicknames = {}; // 保存用户的昵称
let g_channel_id = null;
let g_reconnectInterval = 5000;  // 重连间隔时间，5秒
let g_unreadMessages = 0;
let g_isPageFocused = true;
let g_myNickName = "匿名";
let g_pendingNewMembers = []; // 存储待处理的新成员公钥哈希
let receivedNonces = new Map(); // 存储nonce和时间戳


document.getElementById('upload-image-button').addEventListener('click', function () {
    document.getElementById('image-input').click(); // 触发文件选择
});

document.getElementById('image-input').addEventListener('change', function (event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const base64Image = e.target.result;
            // 显示图片预览
            const imagePreview = document.getElementById('image-preview');
            // 这是不是能防止潜在的DOM XSS（
            // 好像不会，读进来应该就是base64的，不会因为读了什么奇怪东西就引入XSS，不过加了也不会慢很多，管他呢（逃
            if (isValidBase64Image(base64Image)) {
                imagePreview.innerHTML = `<img src="${base64Image}" style="max-width:200px;">`;
                // 存储图片数据，以便发送
                imagePreview.dataset.base64 = base64Image;
                document.getElementById('input-message').focus(); // 图片加载后聚焦到输入框
            } else {
                alert("好像读取到的不是图片格式。");
            }
        };
        reader.readAsDataURL(file);
    }
});

function innerSendImageBase64(base64Image) {
    const encryptedMessage = encryptMessage(JSON.stringify({ base64Image: base64Image, change_nickname: g_myNickName }));
    g_websocket.send(JSON.stringify({
        action: 'send_message', channel_id: g_channel_id, encrypted_message: encryptedMessage
    }));
    // 展示自己的消息
    const myPublicKeyHash = getPublicKeyHash(g_myPublicKey);
    const myNickname = g_myNickName;
    const fingerprint = getShortHash(myPublicKeyHash);
    const fingerprintColor = getColorFromSHA256(myPublicKeyHash);
    appendImageToChatBox(myNickname, fingerprint, base64Image, fingerprintColor);
}

function innerSendMessage(message) {
    const encryptedMessage = encryptMessage(JSON.stringify({ message: message, change_nickname: g_myNickName }));
    g_websocket.send(JSON.stringify({
        action: 'send_message', channel_id: g_channel_id, encrypted_message: encryptedMessage
    }));
}

function updatePageTitle() {
    if (g_channel_id) {
        if (g_unreadMessages > 0) {
            document.title = `(${g_unreadMessages}) ?${g_channel_id}`;
        } else {
            document.title = g_channel_id;
        }
    }
}

document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') {
        g_isPageFocused = true;
        g_unreadMessages = 0; // 重置未读消息计数
        updatePageTitle();
    } else {
        g_isPageFocused = false;
    }
});

forge.util.encodeUtf8 = function (str) {
    return unescape(encodeURIComponent(str));
};

forge.util.decodeUtf8 = function (bytes) {
    return decodeURIComponent(escape(bytes));
};

function getPublicKeyHash(curKey) {
    const publicKeyDer = forge.pki.publicKeyToAsn1(curKey);
    const publicKeyDerBytes = forge.asn1.toDer(publicKeyDer).getBytes();
    const md = forge.md.sha256.create();
    md.update(publicKeyDerBytes);
    return md.digest().toHex();  // 返回十六进制格式的哈希值
}

function getColorFromSHA256(sha256) {
    if (sha256.length !== 64) {
        throw new Error('Invalid SHA256 hash');
    }

    const lastSixBytes = sha256.slice(-6);

    return "#" + lastSixBytes;
}

function sha256ToBase64Prefix(sha256Str) {
    // 检查输入是否为64个字符的SHA-256字符串
    if (sha256Str.length !== 64 || !/^[0-9a-fA-F]+$/.test(sha256Str)) {
        throw new Error("Invalid SHA-256 string");
    }

    // 将SHA-256字符串转换为二进制字节流
    const byteArray = [];
    for (let i = 0; i < sha256Str.length; i += 2) {
        const byte = parseInt(sha256Str.substring(i, i + 2), 16);
        byteArray.push(byte);
    }

    // 将字节数组转换为Base64编码字符串
    const binaryStr = String.fromCharCode(...byteArray);
    const base64Str = btoa(binaryStr);

    // 返回Base64编码的前8个字符
    return base64Str.substring(0, 8);
}

function getShortHash(hash) {
    return sha256ToBase64Prefix(hash);
}

function appendPlainMessageToChatBox(message) {
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const messageText = document.createTextNode(`${message}`);
    messageElem.appendChild(messageText);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function innerAppendMessageToChatBox(nickname, fingerprint, message, fingerprintColor) {
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');

    const nicknameText = document.createTextNode(` ${nickname}: `);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = fingerprint;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(nicknameText);
    messageElem.appendChild(document.createTextNode(message));

    // 安全地处理换行符
    // const lines = message.split('\n');
    // lines.forEach((line, index) => {
    //     messageElem.appendChild(document.createTextNode(line));
    //     if (index < lines.length - 1) {
    //         messageElem.appendChild(document.createElement('br'));
    //     }
    // });

    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function isValidBase64Image(message) {
    // TODO: 可以考虑支持更多格式，但是我不确定哪些格式可能引入潜在的XSS或者IP泄露风险
    // 正则表达式，检查是否以"data:image/jpeg;base64,"开头，后跟base64编码
    const regex = /^data:image\/(jpeg|png|gif|bmp|webp|tiff|svg\+xml|ico|heic);base64,([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

    // 使用正则表达式测试输入的message
    if (regex.test(message)) {
        console.log('是正确图片base64编码');
        return true; // 如果匹配，返回true
    } else {
        console.warn(`${message}可能是恶意的XSS payload！不符合base64图片规则！`);
        return false; // 如果不匹配，返回false
    }
}

function appendImageToChatBox(nickname, fingerprint, imageBase64, fingerprintColor) {
    // 判断是否符合，不符合的话可能是恶意构造的XSS。
    if (!isValidBase64Image(imageBase64)) {
        console.log("isValidBase64Image失败！这可能是一次黑客攻击！");
        return;
    }

    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');

    const nicknameText = document.createTextNode(` ${nickname}`);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = fingerprint;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    const closingParenText = document.createTextNode(`:`);
    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(nicknameText);
    messageElem.appendChild(closingParenText);
    chatBox.appendChild(messageElem);
    chatBox.innerHTML += `<img src="${imageBase64}" style="max-width:600px;">`;
    chatBox.scrollTop = chatBox.scrollHeight;
}

function appendMessageToChatBox(nickname, fingerprint, message, fingerprintColor) {
    innerAppendMessageToChatBox(nickname, fingerprint, message, fingerprintColor);
}

function generateRandomChannel() {
    let randomChannel = '';
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 8; i++) {
        randomChannel += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return randomChannel;
}

document.addEventListener('DOMContentLoaded', function () {
    const queryString = window.location.search.substring(1); // 去掉前面的 '?'
    const channelId = queryString ? queryString : null; // 如果有查询参数，则取其值，否则返回 null
    console.log("channelid = " + channelId);

    const dynamicStylesheet = document.getElementById('dynamic-stylesheet');

    if (channelId) {
        dynamicStylesheet.href = 'style_chat-container.css'; // 加载聊天窗口的CSS文件
        document.getElementById('status-message').innerText = '正在生成 RSA 密钥...';
        g_myPrivateKey = forge.pki.rsa.generateKeyPair(2048).privateKey;
        g_myPublicKey = forge.pki.rsa.setPublicKey(g_myPrivateKey.n, g_myPrivateKey.e);
        g_channel_id = channelId;
        updatePageTitle();
        connectWebSocket();
        // 隐藏主页，显示聊天容器
        document.getElementById('home-container').style.display = 'none';
        document.getElementById('chat-container').style.display = 'block';
    } else {
        // 先把当前的网址链接填进去
        const currentUrl = window.location.origin;
        // Update example links
        document.getElementById('example-channel-link').href = `${currentUrl}/?your-channel`;
        document.getElementById('example-channel-link').textContent = `${currentUrl}/?your-channel`;
        document.getElementById('lounge-link').href = `${currentUrl}/?lounge`;
        document.getElementById('programming-link').href = `${currentUrl}/?programming`;
        document.getElementById('games-link').href = `${currentUrl}/?games`;
        document.getElementById('example-channel-code').textContent = `${currentUrl}/?lounge`;
        // 生成随机频道链接
        const randomChannelLink = document.getElementById('random-channel-link');
        const randomChannelName = generateRandomChannel();
        randomChannelLink.href = `${currentUrl}/?${randomChannelName}`;
        randomChannelLink.textContent = `?${randomChannelName}`;

        dynamicStylesheet.href = 'style_home-container.css';
        // 显示主页，隐藏聊天容器
        document.getElementById('home-container').style.display = 'block';
        document.getElementById('chat-container').style.display = 'none';


    }



    document.getElementById('send-message-button').addEventListener('click', function () {
        sendMessage();
        const imagePreview = document.getElementById('image-preview');
        if (imagePreview.dataset.base64) {
            innerSendImageBase64(imagePreview.dataset.base64); // 发送图片
            imagePreview.innerHTML = ''; // 清空预览
            delete imagePreview.dataset.base64; // 清除存储的图片数据
        }
    });

    // 监听按 Enter 键发送消息和 Shift+Enter 换行
    document.getElementById('input-message').addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();  // 阻止默认的 Enter 行为
            const imagePreview = document.getElementById('image-preview');
            sendMessage();
            if (imagePreview.dataset.base64) {
                console.log(imagePreview.dataset.base64);
                innerSendImageBase64(imagePreview.dataset.base64); // 发送图片
                imagePreview.innerHTML = ''; // 清空预览
                delete imagePreview.dataset.base64; // 清除存储的图片数据
            }
        }
    });

    document.getElementById('save-nickname-button').addEventListener('click', function () {
        const nickname = document.getElementById('nickname-input').value.trim();
        if (nickname !== '') {
            changeNickname(nickname);
            $('#nicknameModal').modal('hide');
        }
    });

    // 定期清理过期的nonce，每分钟执行一次
    setInterval(cleanExpiredNonces, nonceCleanUpInterval);
});

function cleanExpiredNonces() {
    console.log(`inside cleanExpiredNonces function`);
    const currentTime = Date.now();
    for (let [nonce, timestamp] of receivedNonces.entries()) {
        if (currentTime - timestamp > nonceLifeTime) { // 5分钟
            console.log(`deleting ${nonce}`);
            receivedNonces.delete(nonce);
        }
    }
}

function connectWebSocket() {
    g_websocket = new WebSocket(g_uri);
    g_websocket.onopen = function () {
        console.log("WebSocket 已连接");
        joinChannel(g_channel_id);
    };
    g_websocket.onmessage = function (event) {
        handleIncomingMessage(event.data);
    };
    g_websocket.onerror = function (error) {
        console.error('WebSocket Error: ' + error);
    };
    g_websocket.onclose = function (event) {
        console.log('WebSocket closed, attempting to reconnect...', event.reason);
        setTimeout(connectWebSocket, g_reconnectInterval);
    };
}

function appendMyFingerprintToChatBox() {
    const myPublicKeyHash = getPublicKeyHash(g_myPublicKey);
    const fingerprint = getShortHash(myPublicKeyHash);
    const fingerprintColor = getColorFromSHA256(myPublicKeyHash);
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = `我的指纹: ${fingerprint}`;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    messageElem.appendChild(fingerprintSpan);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function joinChannel(channelId) {
    const publicKeyPem = forge.pki.publicKeyToPem(g_myPublicKey);
    g_websocket.send(JSON.stringify({
        action: 'join',
        channel_id: channelId,
        public_key: publicKeyPem
    }));
    document.getElementById('status-message').innerText = '加入成功';
    document.getElementById('input-message').disabled = false; // 启用消息输入框
    updateUsersList(); // 更新用户列表
    appendMyFingerprintToChatBox(); // Append fingerprint to chat box
}

function sendMessage() {
    const input = document.getElementById('input-message');
    const message = input.value.trim();
    input.value = '';  // 清空输入框
    if (message !== '') {
        innerSendMessage(message);
        // 展示自己的消息
        const myPublicKeyHash = getPublicKeyHash(g_myPublicKey);
        const myNickname = g_myNickName;
        const fingerprint = getShortHash(myPublicKeyHash);
        const fingerprintColor = getColorFromSHA256(myPublicKeyHash);
        appendMessageToChatBox(myNickname, fingerprint, message, fingerprintColor);
    }
}

function encryptMessage(message) {
    if (!g_aesKey) {
        console.error('AES key not set');
        return '';
    }
    const nonce = forge.random.getBytesSync(16);
    const timestamp = Date.now();
    const messageWithNonceAndTimestamp = JSON.stringify({
        nonce: forge.util.encode64(nonce),
        timestamp: timestamp,
        message: message
    });

    const cipher = forge.cipher.createCipher('AES-CTR', g_aesKey);
    const iv = forge.random.getBytesSync(16);
    cipher.start({ iv: iv });

    const utf8Message = forge.util.encodeUtf8(messageWithNonceAndTimestamp);
    cipher.update(forge.util.createBuffer(utf8Message));
    if (!cipher.finish()) {
        console.error('Encryption failed');
        return '';
    }
    const encrypted = cipher.output.getBytes();

    const md = forge.md.sha256.create();
    md.update(utf8Message, 'utf8');
    const digest = md.digest().bytes();

    const signature = g_myPrivateKey.sign(md);

    return JSON.stringify({
        nonce: forge.util.encode64(iv),
        ciphertext: forge.util.encode64(encrypted),
        signature: forge.util.encode64(signature)
    });
}

function handleIncomingMessage(data) {
    const messageData = JSON.parse(data);
    switch (messageData.action) {
        case 'heartbeat':
            sendHeartbeat();
            break;
        case 'receive_message':
            console.log(data);
            handleIncomeMessage(messageData.encrypted_message, messageData.public_key_hash);
            if (!g_isPageFocused) {
                g_unreadMessages++;
                updatePageTitle();
            }
            break;
        case 'receive_public_key':
            console.log(data);
            const publicKey = forge.pki.publicKeyFromPem(messageData.public_key);
            if (!g_otherPublicKeys.hasOwnProperty(messageData.public_key_hash)) {
                g_otherPublicKeys[messageData.public_key_hash] = publicKey;
                handleNewMemberJoin(messageData.public_key_hash);
                if (!g_isPageFocused) {
                    g_unreadMessages++;
                    updatePageTitle();
                }
            }
            break;
        case 'generate_aes_key':
            console.log(data);
            generateAndSendAESKey();
            break;
        case 'receive_key':
            console.log(data);
            handleReceiveKey(messageData);
            break;
        case 'member_left':
            console.log(data);
            handleMemberLeft(messageData.public_key_hash);
            if (!g_isPageFocused) {
                g_unreadMessages++;
                updatePageTitle();
            }
            break;
        default:
            console.warn('Unknown action:', messageData.action);
    }
}

function handleReceiveKey(data) {
    const nonce = forge.util.decode64(data.nonce);
    const timestamp = data.timestamp;
    const encryptedKey = data.encrypted_key;
    const signature = data.signature;
    const senderPublicKeyHash = data.sender_public_key_hash;

    // 检查时间戳是否过期
    if ((Date.now() - timestamp) > nonceLifeTime) {
        console.warn('Received key timestamp expired');
        return;
    }

    // 检查 nonce 是否已被使用
    if (receivedNonces.has(nonce)) {
        console.warn('Replay attack detected');
        return;
    }

    receivedNonces.set(nonce, timestamp);

    // 验证签名
    const publicKey = g_otherPublicKeys[senderPublicKeyHash];
    if (!publicKey) {
        console.error('Public key not found for hash:', senderPublicKeyHash);
        return;
    }

    const t_aesKey = g_myPrivateKey.decrypt(forge.util.decode64(encryptedKey), 'RSA-OAEP', {
        md: forge.md.sha256.create(), mgf1: {
            md: forge.md.sha256.create()
        }
    });

    const messageWithNonceAndTimestamp = JSON.stringify({
        nonce: data.nonce,
        timestamp: data.timestamp,
        aesKey: forge.util.encode64(t_aesKey),
    });
    console.log(`接收方messageWithNonceAndTimestamp为 ${messageWithNonceAndTimestamp}`)

    const md = forge.md.sha256.create();
    md.update(messageWithNonceAndTimestamp, 'utf8');
    if (!publicKey.verify(md.digest().bytes(), forge.util.decode64(signature))) {
        console.error('Signature verification failed');
        return;
    }

    // 检验通过了，可以放到g_aesKey。前面检验有一个不通过都不行。
    g_aesKey = t_aesKey;

    // 处理所有待处理的新成员
    sendNicknamesToNewMembers();
}

function sendHeartbeat() {
    const message = JSON.stringify({ action: 'heartbeat' });
    g_websocket.send(message);
}

function handleIncomeMessage(encryptedMessage, publicKeyHash) {
    const messageData = JSON.parse(encryptedMessage);
    const iv = forge.util.decode64(messageData.nonce);
    const ciphertext = forge.util.decode64(messageData.ciphertext);
    const signature = messageData.signature;
    const decipher = forge.cipher.createDecipher('AES-CTR', g_aesKey);
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(ciphertext));
    if (!decipher.finish()) {
        console.error('Decryption failed');
        return;
    }
    const utf8MessageBytes = decipher.output.getBytes();
    const utf8Message = forge.util.decodeUtf8(utf8MessageBytes);

    if (verifySignature(publicKeyHash, utf8MessageBytes, signature)) {
        try {
            const messageJson = JSON.parse(utf8Message);
            const receivedNonce = messageJson.nonce;
            const timestamp = messageJson.timestamp;

            if (receivedNonces.has(receivedNonce) || (Date.now() - timestamp) > nonceLifeTime) { // 5分钟
                console.warn('Message replay detected or timestamp expired');
                return;
            }

            receivedNonces.set(receivedNonce, timestamp);
            console.log(messageJson);
            const innerMessageJson = JSON.parse(messageJson.message);
            handleIncomeMessageJsonFields(publicKeyHash, innerMessageJson);
        } catch (e) {
            console.error('Failed to parse JSON message:', e);
        }
    } else {
        console.error('Signature verification failed');
    }
}

function handleIncomeMessageJsonFields(publicKeyHash, json) {
    for (const key in json) {
        if (json.hasOwnProperty(key)) {
            if (key === 'change_nickname') {
                handleChangeNickname(publicKeyHash, json[key]);
            } else if (key === 'message') {
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                appendMessageToChatBox(nickname, fingerprint, json[key], fingerprintColor);
            } else if (key == 'base64Image') {
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                appendImageToChatBox(nickname, fingerprint, json[key], fingerprintColor);
            } else {
                console.warn(`Unknown field: ${key}`);
            }
        }
    }
}

function verifySignature(publicKeyHash, utf8MessageBytes, signature) {
    const publicKey = g_otherPublicKeys[publicKeyHash];
    if (!publicKey) {
        console.error('Public key not found for hash:', publicKeyHash);
        return false;
    }
    const md = forge.md.sha256.create();
    md.update(utf8MessageBytes, 'utf8');
    try {
        return publicKey.verify(md.digest().bytes(), forge.util.decode64(signature));
    } catch (e) {
        console.error('Signature verification failed:', e);
        return false;
    }
}

function generateAndSendAESKey() {
    g_aesKey = forge.random.getBytesSync(32);
    const nonce = forge.random.getBytesSync(16);
    const timestamp = Date.now();
    const messageWithNonceAndTimestamp = JSON.stringify({
        nonce: forge.util.encode64(nonce),
        timestamp: timestamp,
        aesKey: forge.util.encode64(g_aesKey)
    });
    console.log(`发送方messageWithNonceAndTimestamp为：${messageWithNonceAndTimestamp}`)

    const md = forge.md.sha256.create();
    md.update(messageWithNonceAndTimestamp, 'utf8');
    const signature = g_myPrivateKey.sign(md);

    const myPublicKeyHash = getPublicKeyHash(g_myPublicKey);

    for (let hash in g_otherPublicKeys) {
        const publicKey = g_otherPublicKeys[hash];
        const encryptedKey = publicKey.encrypt(g_aesKey, 'RSA-OAEP', {
            md: forge.md.sha256.create(), mgf1: {
                md: forge.md.sha256.create()
            }
        });
        g_websocket.send(JSON.stringify({
            action: 'send_key',
            channel_id: g_channel_id,
            encrypted_key: forge.util.encode64(encryptedKey),
            public_key_hash: hash,
            sender_public_key_hash: myPublicKeyHash,
            nonce: forge.util.encode64(nonce),
            timestamp: timestamp,
            signature: forge.util.encode64(signature)
        }));
    }
}

function handleMemberLeft(publicKeyHash) {
    delete g_otherPublicKeys[publicKeyHash];
    updateUsersList();
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const messageText1 = document.createTextNode(`用户 `);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = `${getShortHash(publicKeyHash)}`;
    fingerprintSpan.style.color = getColorFromSHA256(publicKeyHash);
    fingerprintSpan.classList.add("message-text");
    const messageText2 = document.createTextNode(` 已离开。`);
    messageElem.appendChild(messageText1);
    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(messageText2);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function handleNewMemberJoin(publicKeyHash) {
    g_userNicknames[publicKeyHash] = "匿名";
    updateUsersList();
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const messageText1 = document.createTextNode(`新成员加入: `);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = `${getShortHash(publicKeyHash)}`;
    fingerprintSpan.style.color = getColorFromSHA256(publicKeyHash);
    fingerprintSpan.classList.add("message-text");
    messageElem.appendChild(messageText1);
    messageElem.appendChild(fingerprintSpan);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;

    // 添加到待处理队列而不是立即发送昵称
    g_pendingNewMembers.push(publicKeyHash);
}

function sendNicknamesToNewMembers() {
    while (g_pendingNewMembers.length > 0) {
        const publicKeyHash = g_pendingNewMembers.shift(); // 从队列中取出一个新成员
        sendNicknamesToNewMember(publicKeyHash);
    }
}

function sendNicknamesToNewMember(newMemberPublicKeyHash) {
    if (g_myNickName !== "匿名") {
        const encryptedMessage = encryptMessage(JSON.stringify({ change_nickname: g_myNickName }));
        g_websocket.send(JSON.stringify({
            action: 'send_message', channel_id: g_channel_id, encrypted_message: encryptedMessage
        }));
    }
}

function updateUsersList() {
    const usersList = document.getElementById('users-list');
    usersList.innerHTML = "";
    const totalUsers = Object.keys(g_otherPublicKeys).length + 1;

    const totalUsersParagraph = document.createElement('p');
    totalUsersParagraph.textContent = `在线用户: ${totalUsers}`;

    const selfInfoParagraph = document.createElement('p');
    selfInfoParagraph.textContent = '我: 自己';

    usersList.appendChild(totalUsersParagraph);
    usersList.appendChild(selfInfoParagraph);

    for (let publicKeyHash in g_otherPublicKeys) {
        const nickname = getNickname(publicKeyHash);
        const fingerprint = getShortHash(publicKeyHash);
        const fingerprintColor = getColorFromSHA256(publicKeyHash);

        const userInfoParagraph = document.createElement('p');
        const nicknameText = document.createTextNode(`${nickname} (`);
        const fingerprintSpan = document.createElement('span');
        fingerprintSpan.textContent = fingerprint;
        fingerprintSpan.style.color = fingerprintColor;
        const closingParenText = document.createTextNode(`): 其他用户`);

        userInfoParagraph.appendChild(nicknameText);
        userInfoParagraph.appendChild(fingerprintSpan);
        userInfoParagraph.appendChild(closingParenText);
        usersList.appendChild(userInfoParagraph);
    }

    const statusMessage = document.getElementById('status-message');
    statusMessage.innerText = `当前频道：${g_channel_id}（在线用户: ${totalUsers}）`;
}

function changeNickname(nickname) {
    g_myNickName = nickname;
    const encryptedMessage = encryptMessage(JSON.stringify({ change_nickname: nickname }));
    g_websocket.send(JSON.stringify({
        action: 'send_message', channel_id: g_channel_id, encrypted_message: encryptedMessage
    }));
    // 展示昵称变更的消息
    const myPublicKeyHash = getPublicKeyHash(g_myPublicKey);
    const fingerprint = getShortHash(myPublicKeyHash);
    const fingerprintColor = getColorFromSHA256(myPublicKeyHash);
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = `${fingerprint}`;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    const messageText1 = document.createTextNode(` 设置新昵称: ${nickname}`);
    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(messageText1);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;

}

function handleChangeNickname(publicKeyHash, nickname) {
    // 如果已经设置了，不用修改。
    if (g_userNicknames[publicKeyHash] === nickname) {
        return;
    }
    g_userNicknames[publicKeyHash] = nickname;
    updateUsersList();
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = `${getShortHash(publicKeyHash)}`;
    fingerprintSpan.style.color = getColorFromSHA256(publicKeyHash);
    fingerprintSpan.classList.add("message-text");
    const messageText1 = document.createTextNode(` 设置新昵称: ${nickname}`);
    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(messageText1);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function getNickname(publicKeyHash) {
    return g_userNicknames[publicKeyHash] || '匿名';
}
