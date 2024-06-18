const g_uri = 'wss://ws.0f31.com:8765';
const nonceLifeTime = 300000; // nonce的生命是5分钟
const nonceCleanUpInterval = 60000; // 每隔1分钟清理一次nonce
let g_websocket = null;
let g_myPrivateKey = null;
let g_myPublicKey = null;
let g_effective_aes_key = null; // 这个是真正用来做加解密的真实aes密钥
let g_exchange_aes_key = null; // 这个是交换的时候用的aes密钥。
let g_otherPublicKeys = {};
let g_userNicknames = {}; // 保存用户的昵称
let g_hashed_channel_id = null;
let g_real_channel_id = null;
let g_reconnectInterval = 5000;  // 重连间隔时间，5秒
let g_unreadMessages = 0;
let g_isPageFocused = true;
let g_myNickName = "匿名";
let g_pendingNewMembers = []; // 存储待处理的新成员公钥哈希
let receivedNonces = new Map(); // 存储nonce和时间戳
let g_salt1 = "https://github.com/smallzhong/E2EEGroupChat";
let g_salt2 = "smallzhong";
const g_MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB


function loadPrivateKey() {
    try {
        const pemKey = document.getElementById('rsa-key-input').value.trim();
        if (!pemKey) {
            alert('请输入有效的私钥');
            return;
        }
        g_myPrivateKey = forge.pki.privateKeyFromPem(pemKey);
        g_myPublicKey = forge.pki.rsa.setPublicKey(g_myPrivateKey.n, g_myPrivateKey.e);
        connectWebSocket();
        $('#rsaKeysModal').modal('hide');
    } catch (error) {
        alert('加载密钥失败，请确保密钥格式正确');
        console.error('Error loading private key:', error);
    }
}

document.getElementById('upload-file-button').addEventListener('click', function () {
    document.getElementById('file-input').click();
});
document.getElementById('file-input').addEventListener('change', function (event) {
    const file = event.target.files[0];
    if (file) {
        if (file.size > g_MAX_FILE_SIZE) {
            alert('文件过大，请选择一个小于5MB的文件。');
            return;
        }
        const reader = new FileReader();
        reader.onload = function (e) {
            const base64File = e.target.result;
            const fileName = file.name;
            appendFileToChatBox(g_myNickName, getShortHash(getPublicKeyHash(g_myPublicKey)), base64File, fileName, getColorFromSHA256(getPublicKeyHash(g_myPublicKey)));
            innerSendFileBase64(base64File, fileName);
        };
        reader.readAsDataURL(file);
    }
});

function innerSendFileBase64(base64File, fileName) {
    const encryptedMessage = encryptMessage(JSON.stringify({ base64File: base64File, fileName: fileName, change_nickname: g_myNickName }));
    g_websocket.send(JSON.stringify({
        action: 'send_message', channel_id: g_hashed_channel_id, encrypted_message: encryptedMessage
    }));
}

function appendFileToChatBox(nickname, fingerprint, base64File, fileName, fingerprintColor) {
    if (!isValidBase64File(base64File) || !isValidFileName(fileName)) {
        console.warn("文件验证失败！这可能是一次黑客攻击！");
        return;
    }

    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    const nicknameText = document.createTextNode(` ${nickname}`);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = fingerprint;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    const closingParenText = document.createTextNode(`: `);
    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(nicknameText);
    messageElem.appendChild(closingParenText);

    const fileLink = document.createElement('a');
    fileLink.href = base64File;
    fileLink.download = fileName;
    fileLink.textContent = fileName;
    fileLink.style.color = '#007bff';
    fileLink.style.textDecoration = 'underline';

    messageElem.appendChild(fileLink);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}


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

document.getElementById('input-message').addEventListener('paste', function (event) {
    if (event.clipboardData && event.clipboardData.items) {
        const items = event.clipboardData.items;
        for (let i = 0; i < items.length; i++) {
            if (items[i].kind === 'file') {
                const blob = items[i].getAsFile();
                const reader = new FileReader();
                reader.onload = function (e) {
                    const base64File = e.target.result;
                    const fileName = blob.name;
                    if (blob.type.startsWith('image/')) {
                        if (isValidBase64Image(base64File)) {
                            const imagePreview = document.getElementById('image-preview');
                            imagePreview.innerHTML = `<img src="${base64File}" style="max-width:200px;">`;
                            imagePreview.dataset.base64 = base64File;
                            document.getElementById('input-message').focus();
                        } else {
                            console.warn("粘贴的不是图片格式。");
                        }
                    } else {
                        if (isValidBase64File(base64File)) {
                            const filePreview = document.getElementById('image-preview'); // 使用相同的预览区域
                            filePreview.innerHTML = `<p>文件名: ${fileName}</p>`;
                            filePreview.dataset.base64 = base64File;
                            filePreview.dataset.fileName = fileName;
                            document.getElementById('input-message').focus();
                        } else {
                            console.warn("粘贴的不是有效的文件格式。");
                        }
                    }
                };
                reader.readAsDataURL(blob);
            }
        }
    }
});

const SLICE_SIZE = 1024 * 1024; // 1MB
function generateUniqueId() {
    return 'image_' + Math.random().toString(36).substr(2, 9);
}
function innerSendImageBase64(base64Image) {
    const totalSlices = Math.ceil(base64Image.length / SLICE_SIZE);
    const imageId = generateUniqueId(); // 生成唯一的图片ID
    for (let i = 0; i < totalSlices; i++) {
        const slice = base64Image.slice(i * SLICE_SIZE, (i + 1) * SLICE_SIZE);
        const encryptedMessage = encryptMessage(JSON.stringify({
            imageData: {
                base64Image: slice,
                imageId: imageId,
                sliceIndex: i,
                totalSlices: totalSlices
            },
            change_nickname: g_myNickName
        }));
        g_websocket.send(JSON.stringify({
            action: 'send_message',
            channel_id: g_hashed_channel_id,
            encrypted_message: encryptedMessage
        }));
    }
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
        action: 'send_message', channel_id: g_hashed_channel_id, encrypted_message: encryptedMessage
    }));
}

function updatePageTitle() {
    if (g_hashed_channel_id) {
        if (g_unreadMessages > 0) {
            document.title = `(${g_unreadMessages}) ?${g_real_channel_id}`;
        } else {
            document.title = `${g_real_channel_id}`;
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
    // 先检查前缀部分
    const prefixRegex = /^data:image\/(jpeg|png|gif|bmp|webp|tiff|svg\+xml|ico|heic);base64,/;
    if (!prefixRegex.test(message)) {
        console.warn(`${message} 不符合base64图片前缀规则！`);
        return false;
    }

    // 获取前缀长度
    const prefixLength = message.match(prefixRegex)[0].length;

    // 合法的Base64字符集合
    const base64Chars = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');

    // 检查其余部分是否为合法的Base64字符
    for (let i = prefixLength; i < message.length; i++) {
        const char = message[i];
        if (!base64Chars.has(char)) {
            console.warn(`${message} 可能是恶意的XSS payload！不符合base64图片内容规则！`);
            return false;
        }
    }

    console.log('是正确图片base64编码');
    return true;
}
function showModal(imageBase64) {
    const modal = document.createElement('div');
    modal.style.position = 'fixed';
    modal.style.top = '0';
    modal.style.left = '0';
    modal.style.width = '100%';
    modal.style.height = '100%';
    modal.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    modal.style.display = 'flex';
    modal.style.alignItems = 'center';
    modal.style.justifyContent = 'center';
    modal.style.zIndex = '1000';

    const largeImage = document.createElement('img');
    largeImage.src = imageBase64;
    largeImage.style.maxWidth = '90%';
    largeImage.style.maxHeight = '90%';

    modal.appendChild(largeImage);

    modal.addEventListener('click', function () {
        document.body.removeChild(modal);
    });

    document.body.appendChild(modal);
}

function isValidBase64File(base64File) {
    // 先检查前缀部分
    const prefixRegex = /^data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,/;
    if (!prefixRegex.test(base64File)) {
        console.warn(`${base64File} 不符合base64文件前缀规则！`);
        return false;
    }

    // 获取前缀长度
    const prefixLength = base64File.match(prefixRegex)[0].length;

    // 合法的Base64字符集合
    const base64Chars = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');

    // 检查其余部分是否为合法的Base64字符
    for (let i = prefixLength; i < base64File.length; i++) {
        const char = base64File[i];
        if (!base64Chars.has(char)) {
            console.warn(`${base64File} 可能是恶意的XSS payload！不符合base64文件内容规则！`);
            return false;
        }
    }

    console.log('是正确的base64文件编码');
    return true;
}


function isValidFileName(fileName) {
    const invalidChars = /[<>:"/\\|?*\x00-\x1F]/g;
    if (invalidChars.test(fileName)) {
        alert(`文件名${fileName}包含非法字符！`);
        console.warn(`文件名${fileName}包含非法字符！`);
        return false;
    }
    return true;
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

    const imageElem = document.createElement('img');
    imageElem.src = imageBase64;
    imageElem.style.maxWidth = '600px';
    imageElem.addEventListener('click', function () {
        showModal(imageBase64);
    });

    chatBox.appendChild(messageElem);
    chatBox.appendChild(imageElem);
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

function generateHMACBytes(original, salt) {
    const hmac = forge.hmac.create();
    hmac.start('sha256', salt);
    hmac.update(original);
    const hmacResult = hmac.digest().bytes();
    console.log(`generateHMACBytes original=${original} salt=${salt} hmacResult=${forge.util.encode64(hmacResult)}`);
    return hmacResult;
}

function generateHMACString(original, salt) {
    return forge.util.bytesToHex(generateHMACBytes(original, salt));
}

function getHashedChannelId(real_channel_id) {
    return generateHMACString(real_channel_id, g_salt1);
}

function getEffectiveAesKey(exchange_aes_key, hmacBytes) {
    if (exchange_aes_key.length !== hmacBytes.length) {
        throw new Error('Both inputs must be of the same length');
    }

    let xorResult = '';
    for (let i = 0; i < exchange_aes_key.length; i++) {
        // XOR the byte values and convert them back to a byte string
        xorResult += String.fromCharCode(exchange_aes_key.charCodeAt(i) ^ hmacBytes.charCodeAt(i));
    }

    console.log(`getEffectiveAesKey结果${forge.util.encode64(xorResult)}`);
    return xorResult;
}

function joinChannelProcess(channelName) {
    // 设置 URL 的哈希部分
    window.location.hash = 'chat';

    g_real_channel_id = channelName;
    g_hashed_channel_id = getHashedChannelId(channelName);
    initializeChatInterface(); // 用来设置界面和初始化密钥等
}

function initializeChatInterface() {
    document.getElementById('dynamic-stylesheet').href = 'style_chat-container.css';
    document.getElementById('status-message').innerText = '正在生成 RSA 密钥...';
    g_myPrivateKey = forge.pki.rsa.generateKeyPair(2048).privateKey;
    g_myPublicKey = forge.pki.rsa.setPublicKey(g_myPrivateKey.n, g_myPrivateKey.e);
    updatePageTitle();
    connectWebSocket();

    // 切换显示内容
    document.getElementById('home-container').style.display = 'none';
    document.getElementById('chat-container').style.display = 'block';
}

window.addEventListener('hashchange', handleHashChange);
// window.addEventListener('load', handleHashChange);

function handleHashChange() {
    const hash = window.location.hash;
    if (hash === '#chat' && g_hashed_channel_id) {
        // initializeChatInterface();
    } else {
        if (g_websocket && g_websocket.readyState !== WebSocket.CLOSED) {
            console.log('hash改变了，而当前websocket还是connect状态，给close掉。');
            g_websocket.onclose = null;
            g_websocket.close();
        }
        // 显示主页
        window.location.hash = "";
        document.getElementById('dynamic-stylesheet').href = 'style_home-container.css';
        document.getElementById('home-container').style.display = 'block';
        document.getElementById('chat-container').style.display = 'none';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    window.location.hash = "";
    const channelInput = document.getElementById('channel-name-input');
    const randomChannelName = generateRandomChannel();
    channelInput.value = randomChannelName;  // 填充随机频道名称

    channelInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {  // 检测回车键
            e.preventDefault();  // 阻止默认行为
            joinChannelProcess(channelInput.value.trim());  // 加入频道
        }
    });

    document.getElementById('join-channel-button').addEventListener('click', function () {
        const channelName = document.getElementById('channel-name-input').value.trim();
        if (channelName) {
            joinChannelProcess(channelName);
        } else {
            alert("Please enter a channel name.");
        }
    });

    // 显示主页，隐藏聊天容器
    // document.getElementById('home-container').style.display = 'block';
    // document.getElementById('chat-container').style.display = 'none';

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
                if (imagePreview.dataset.fileName) {
                    // 发送文件
                    console.log(imagePreview.dataset.base64, imagePreview.dataset.fileName);
                    appendFileToChatBox(g_myNickName, getShortHash(getPublicKeyHash(g_myPublicKey)), imagePreview.dataset.base64, imagePreview.dataset.fileName, getColorFromSHA256(getPublicKeyHash(g_myPublicKey)));
                    innerSendFileBase64(imagePreview.dataset.base64, imagePreview.dataset.fileName); // 发送文件
                    imagePreview.innerHTML = ''; // 清空预览
                    delete imagePreview.dataset.base64; // 清除存储的文件数据
                    delete imagePreview.dataset.fileName; // 清除存储的文件名
                } else {
                    // 发送图片
                    console.log(imagePreview.dataset.base64);
                    innerSendImageBase64(imagePreview.dataset.base64); // 发送图片
                    imagePreview.innerHTML = ''; // 清空预览
                    delete imagePreview.dataset.base64; // 清除存储的图片数据
                }
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

function displayRSAModal() {
    const rsaKeyPem = forge.pki.privateKeyToPem(g_myPrivateKey);
    document.getElementById('rsa-key-display').value = rsaKeyPem;
    $('#rsaKeysModal').modal('show');
}

function copyToClipboard() {
    const rsaKeyTextarea = document.getElementById('rsa-key-display');
    rsaKeyTextarea.select();
    document.execCommand('copy');
    alert('密钥已复制到剪贴板');
}

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
    if (g_websocket && g_websocket.readyState !== WebSocket.CLOSED) {
        console.log('当前websocket还是connect状态，给close掉。');
        g_websocket.onclose = null;
        g_websocket.close();
    }
    g_websocket = new WebSocket(g_uri);
    g_websocket.onopen = function () {
        console.log("WebSocket 已连接");
        joinChannel(g_hashed_channel_id);
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
    fingerprintSpan.textContent = `加入 ${g_real_channel_id} 成功！我的指纹: ${fingerprint}`;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    messageElem.appendChild(fingerprintSpan);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function joinChannel(hashedChannelId) {
    g_otherPublicKeys = {};
    // TODO: 这里要加入一条新加入消息，不能直接清空，也不能啥也不干。
    // document.getElementById('chat-box').innerText = ""; 
    const publicKeyPem = forge.pki.publicKeyToPem(g_myPublicKey);
    g_websocket.send(JSON.stringify({
        action: 'join',
        channel_id: hashedChannelId,
        public_key: publicKeyPem,

        // 这里加一个字段，hmac(channel_id, 自己公钥签名)。
        // 接收的时候如果这个值不对，说明这个人不知道channel_id的真实值。
        //服务器能知道别人用的这个签名，但是那是别人的公钥，自己的公钥的签名无从得知，那signature字段就是非法的，还是过不去校验。
        channel_id_signature: generateHMACString(g_real_channel_id, getPublicKeyHash(g_myPublicKey)),
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
    if (!g_effective_aes_key) {
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

    const cipher = forge.cipher.createCipher('AES-CTR', g_effective_aes_key);
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
            //console.log(data);
            handleIncomeMessage(messageData.encrypted_message, messageData.public_key_hash);
            break;
        case 'receive_public_key':
            console.log(data);
            const publicKey = forge.pki.publicKeyFromPem(messageData.public_key);
            const channelIdSignature = messageData.channel_id_signature;
            // 这里注意不能用messageData.public_key_hash，因为这个是服务器控制的，服务器可以恶意伪造，如果直接信任了服务器的hash，会导致被攻破
            console.log(`channelIdSignature=${channelIdSignature}`);
            console.log(`generateHMACString(g_real_channel_id, getPublicKeyHash(publicKey))=${generateHMACString(g_real_channel_id, getPublicKeyHash(publicKey))}`);
            console.log(`getPublicKeyHash(publicKey)=${getPublicKeyHash(publicKey)}`);
            console.log(`messageData.public_key_hash=${messageData.public_key_hash}`);
            if (channelIdSignature !== generateHMACString(g_real_channel_id, getPublicKeyHash(publicKey))) {
                // 不合法，不能让他进入我的公钥列表，也不能让用户看到消息以为这个人进来了。
                console.warn(`channelIdSignature !== generateHMACString(g_real_channel_id, getPublicKeyHash(publicKey)) 这个人的公钥不合法！拒绝接受这个人的公钥！`);
            }
            else {
                if (messageData.public_key_hash !== getPublicKeyHash(g_myPublicKey) && !g_otherPublicKeys.hasOwnProperty(messageData.public_key_hash)) {
                    g_otherPublicKeys[messageData.public_key_hash] = publicKey;
                    handleNewMemberJoin(messageData.public_key_hash);
                    if (!g_isPageFocused) {
                        g_unreadMessages++;
                        updatePageTitle();
                    }
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
    const channelIdSignature = data.channel_id_signature;

    if (senderPublicKeyHash === getPublicKeyHash(g_myPublicKey)) {
        console.warn(`senderPublicKeyHash === getPublicKeyHash(g_myPublicKey)`);
        return;
    }

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

    // 验证channel_id_signature签名是否正确
    if (channelIdSignature !== generateHMACString(g_real_channel_id, senderPublicKeyHash)) {
        console.error('channel_id_signature verification failed');
        return;
    }

    // 检验通过了，可以放到g_aesKey。前面检验有一个不通过都不行。

    g_effective_aes_key = getEffectiveAesKey(t_aesKey, generateHMACBytes(g_real_channel_id, g_salt2));
    console.log(`g_effective_aes_key = ${forge.util.encode64(g_effective_aes_key)}`);

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
    const decipher = forge.cipher.createDecipher('AES-CTR', g_effective_aes_key);
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

let imageSlices = {};
let imagePlaceholders = {}; // 存储图片占位符

function handleIncomeMessageJsonFields(publicKeyHash, json) {
    let isNewMessageFlag = true;
    for (const key in json) {
        if (json.hasOwnProperty(key)) {
            if (key === 'change_nickname') {
                handleChangeNickname(publicKeyHash, json[key]);
            } else if (key === 'message') {
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                appendMessageToChatBox(nickname, fingerprint, json[key], fingerprintColor);
            } else if (key === 'imageData') {
                try {
                    const imageData = json[key];
                    if (!imageData) {
                        throw new Error('imageData is undefined');
                    }
                    const { imageId, base64Image, sliceIndex, totalSlices } = imageData;
                    const nickname = getNickname(publicKeyHash);
                    const fingerprint = getShortHash(publicKeyHash);
                    const fingerprintColor = getColorFromSHA256(publicKeyHash);

                    // 如果是分片传输
                    const imageKey = `${publicKeyHash}-${imageId}`;
                    if (!imageSlices[imageKey]) {
                        imageSlices[imageKey] = [];
                        createImagePlaceholder(nickname, fingerprint, fingerprintColor, imageKey, imageId);
                    }
                    imageSlices[imageKey][sliceIndex] = base64Image;

                    // 更新占位符的进度
                    const receivedSlices = imageSlices[imageKey].filter(slice => slice !== undefined).length;
                    updateImagePlaceholder(nickname, fingerprint, fingerprintColor, imageKey, receivedSlices, totalSlices, imageId);

                    // 如果收齐了所有分片
                    if (receivedSlices === totalSlices) {  // 确保所有分片已收到
                        const fullImageBase64 = imageSlices[imageKey].join('');
                        delete imageSlices[imageKey];
                        const placeholderElem = document.getElementById(imageKey);
                        if (placeholderElem) {
                            placeholderElem.remove(); // 移除占位符
                        }
                        appendImageToChatBox(nickname, fingerprint, fullImageBase64, fingerprintColor);
                    } else {
                        isNewMessageFlag = false;
                    }
                } catch (error) {
                    console.error(`Error processing image slice data: ${error.message}`);
                    isNewMessageFlag = false;
                }
            } else if (key === 'base64File') {
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                appendFileToChatBox(nickname, fingerprint, json[key], json.fileName, fingerprintColor);
            } else {
                console.warn(`Unknown field: ${key}`);
                // TODO: 传base64File的时候，有一些字段是会走到这里的，所以这里暂时不能false，有空把前面的封装一遍。
                // isNewMessageFlag = false;
            }
        }
    }

    if (isNewMessageFlag === true && !g_isPageFocused) {
        g_unreadMessages++;
        updatePageTitle();
    }
}

function createImagePlaceholder(nickname, fingerprint, fingerprintColor, imageKey, imageId) {
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');
    messageElem.id = imageKey; // 设置占位符的id

    const nicknameText = document.createTextNode(` ${nickname}`);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = fingerprint;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");
    const closingParenText = document.createTextNode(`: 正在接收图片${imageId} (0%)`);

    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(nicknameText);
    messageElem.appendChild(closingParenText);

    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function updateImagePlaceholder(nickname, fingerprint, fingerprintColor, imageKey, receivedSlices, totalSlices, imageId) {
    const placeholderElem = document.getElementById(imageKey);
    if (placeholderElem) {
        placeholderElem.remove(); // 移除占位符
        const chatBox = document.getElementById('chat-box');
        const messageElem = document.createElement('p');
        messageElem.id = imageKey; // 设置占位符的id

        const nicknameText = document.createTextNode(` ${nickname}`);
        const fingerprintSpan = document.createElement('span');
        fingerprintSpan.textContent = fingerprint;
        fingerprintSpan.style.color = fingerprintColor;
        fingerprintSpan.classList.add("message-text");
        const progress = Math.floor((receivedSlices / totalSlices) * 100);

        const closingParenText = document.createTextNode(`：正在接收图片${imageId} (${progress}%)`);

        messageElem.appendChild(fingerprintSpan);
        messageElem.appendChild(nicknameText);
        messageElem.appendChild(closingParenText);

        chatBox.appendChild(messageElem);
        chatBox.scrollTop = chatBox.scrollHeight;
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
    g_exchange_aes_key = forge.random.getBytesSync(32);
    g_effective_aes_key = getEffectiveAesKey(g_exchange_aes_key, generateHMACBytes(g_real_channel_id, g_salt2));
    const nonce = forge.random.getBytesSync(16);
    const timestamp = Date.now();
    const messageWithNonceAndTimestamp = JSON.stringify({
        nonce: forge.util.encode64(nonce),
        timestamp: timestamp,
        aesKey: forge.util.encode64(g_exchange_aes_key)
    });
    console.log(`发送方messageWithNonceAndTimestamp为：${messageWithNonceAndTimestamp}`)

    const md = forge.md.sha256.create();
    md.update(messageWithNonceAndTimestamp, 'utf8');
    const signature = g_myPrivateKey.sign(md);

    const myPublicKeyHash = getPublicKeyHash(g_myPublicKey);

    for (let hash in g_otherPublicKeys) {
        const publicKey = g_otherPublicKeys[hash];
        const encryptedKey = publicKey.encrypt(g_exchange_aes_key, 'RSA-OAEP', {
            md: forge.md.sha256.create(), mgf1: {
                md: forge.md.sha256.create()
            }
        });
        g_websocket.send(JSON.stringify({
            action: 'send_key',
            channel_id: g_hashed_channel_id,
            encrypted_key: forge.util.encode64(encryptedKey),
            public_key_hash: hash,
            sender_public_key_hash: myPublicKeyHash,
            nonce: forge.util.encode64(nonce),
            timestamp: timestamp,
            signature: forge.util.encode64(signature),

            // 这里加一个字段，hmac(channel_id, 自己公钥签名)。
            // 接收的时候如果这个值不对，说明这个人不知道channel_id的真实值。
            // 服务器能知道别人用的这个签名，但是那是别人的公钥，自己的公钥的签名无从得知，那signature字段就是非法的，还是过不去校验。
            channel_id_signature: generateHMACString(g_real_channel_id, getPublicKeyHash(g_myPublicKey)),
        }));
    }
}

function handleMemberLeft(publicKeyHash) {
    if (!g_otherPublicKeys.hasOwnProperty(publicKeyHash)) {
        console.warn(`这个人${publicKeyHash}没在列表里面，不打印他的退出信息，以免给用户带来混淆。这可能是一次攻击。`);
        return;
    }
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
            action: 'send_message', channel_id: g_hashed_channel_id, encrypted_message: encryptedMessage
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
    statusMessage.innerText = `当前频道：${g_real_channel_id}（在线用户: ${totalUsers}）`;
}

function changeNickname(nickname) {
    g_myNickName = nickname;
    const encryptedMessage = encryptMessage(JSON.stringify({ change_nickname: nickname }));
    g_websocket.send(JSON.stringify({
        action: 'send_message', channel_id: g_hashed_channel_id, encrypted_message: encryptedMessage
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
