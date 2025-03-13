const g_uri = 'wss://chat.yuchu.space:8765';
const g_fileServerBaseUrl = "https://filebase.yuchu.space";
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
let g_imageSlices = {};
let g_imagePlaceholders = {}; // 存储图片占位符
const g_MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
// TODO:感觉分片不太好，还是得http传，不能websocket传。这里先改成不分片。
const g_SLICE_SIZE = 0.5 * 1024 * 1024; // 0.5MB


function handleDragOver(event) {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy'; // 显示复制图标
    document.getElementById('chat-container').classList.add('dragover');
}

// 处理文件拖拽放下事件
function handleDrop(event) {
    event.preventDefault();
    document.getElementById('chat-container').classList.remove('dragover');
    const files = event.dataTransfer.files;
    for (let file of files) {
        if (file.type.startsWith('image/')) {
            handleImageDrop(file);
        } else {
            handleFileDrop(file);
        }
    }
}

// 移除拖拽样式
document.getElementById('chat-container').addEventListener('dragleave', function () {
    document.getElementById('chat-container').classList.remove('dragover');
});

function setImageDisplay(base64Image) {
    const imagePreview = document.getElementById('image-preview');
    if (isValidBase64Image(base64Image)) {
        imagePreview.innerHTML = `<img src="${base64Image}" style="max-width:200px;">`;
        imagePreview.dataset.base64 = base64Image;
        document.getElementById('input-message').focus();
    } else {
        alert("读取的不是图片格式。");
    }
}

function addImagePreview(base64Image) {
    const previewsContainer = document.getElementById('previews-container');
    const previewElem = document.createElement('div');
    previewElem.classList.add('preview-item');
    previewElem.innerHTML = `<img src="${base64Image}" style="max-width:200px; margin: 10px;">`;
    previewElem.dataset.base64 = base64Image;
    previewsContainer.appendChild(previewElem);
    document.getElementById('input-message').focus();

}

function addFilePreview(fileName, base64File) {
    const previewsContainer = document.getElementById('previews-container');
    const previewElem = document.createElement('div');
    previewElem.classList.add('preview-item');
    previewElem.innerHTML = `<p>文件名: ${fileName}</p>`;
    previewElem.dataset.base64 = base64File;
    previewElem.dataset.fileName = fileName;
    previewsContainer.appendChild(previewElem);
    document.getElementById('input-message').focus();

}

// 处理图片拖拽
function handleImageDrop(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
        const base64Image = e.target.result;
        addImagePreview(base64Image);
    };
    reader.readAsDataURL(file);
}

// 处理文件拖拽
function handleFileDrop(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
        const base64File = e.target.result;
        const fileName = file.name;
        addFilePreview(fileName, base64File);
    };
    reader.readAsDataURL(file);
}

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
    const files = event.target.files;
    for (let file of files) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const base64File = e.target.result;
            const fileName = file.name;
            addFilePreview(fileName, base64File);
        };
        reader.readAsDataURL(file);
    }
});

async function uploadFileToServer(content) {
    // 创建一个Blob对象，它代表了一个不可变的、原始数据的类文件对象。
    const file = new Blob([content], { type: 'application/octet-stream' });

    // 创建一个FormData对象，它用来组合键值对以便发送。
    const formData = new FormData();
    formData.append('file', file);

    // 发送POST请求到服务器的/upload端点。
    const response = await fetch(g_fileServerBaseUrl + '/upload', { method: 'POST', body: formData });

    // 解析响应为JSON格式。
    const data = await response.json();

    // 返回上传的路径。
    return g_fileServerBaseUrl + data.url;
}

function sendFileMessage(downloadUrl, fileName, fileHash, aesKey) {
    const encryptedMessage = encryptMessage(JSON.stringify({
        fileInfo: {
            url: downloadUrl,
            fileName: fileName,
            sha256: fileHash,
            aesKey: forge.util.encode64(aesKey), // 用Base64编码AES密钥
        },
        change_nickname: g_myNickName
    }));
    g_websocket.send(JSON.stringify({
        action: 'send_message',
        channel_id: g_hashed_channel_id,
        encrypted_message: encryptedMessage
    }));
}
async function downloadAndVerifyFile(url, expectedHash) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const arrayBuffer = await response.arrayBuffer();
    const decryptedFile = decryptFileWithAES(arrayBuffer, expectedHash);

    if (calculateSHA256(decryptedFile) !== expectedHash) {
        throw new Error("File hash does not match expected hash.");
    }
    return decryptedFile;
}

function encryptFileWithAES(file, aesKey) {
    const cipher = forge.cipher.createCipher('AES-CTR', aesKey);
    const iv = forge.random.getBytesSync(16);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(file));
    cipher.finish();
    return iv + cipher.output.getBytes(); // 返回IV和密文的组合
}

function decryptFileWithAES(encryptedContent, aesKey) {
    const iv = encryptedContent.slice(0, 16); // 前16个字节为IV
    const encryptedData = encryptedContent.slice(16);

    const decipher = forge.cipher.createDecipher('AES-CTR', aesKey);
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(encryptedData));
    if (!decipher.finish()) {
        throw new Error('Decryption failed');
    }
    return decipher.output.getBytes(); // 返回解密后的数据
}

async function innerSendFileBase64(file, fileName) {
    try {
        const aesKey = forge.random.getBytesSync(32); // 生成一个新的AES密钥
        const encryptedFile = encryptFileWithAES(atob(file.split(',')[1]), aesKey); // 用AES密钥加密文件 (去掉 base64 前缀)
        const downloadUrl = await uploadFileToServer(encryptedFile); // 上传加密后的文件
        const fileHash = calculateSHA256(atob(file.split(',')[1])); // 计算原始文件的哈希值

        console.log(`downloadUrl = ${downloadUrl}`);
        sendFileMessage(downloadUrl, fileName, fileHash, aesKey); // 发送文件消息和AES密钥
    } catch (error) {
        console.error("Error processing file:", error);
    }
}

async function downloadAndDecryptFile(url, aesKeyBase64) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const encryptedContent = await response.text();
    const aesKey = forge.util.decode64(aesKeyBase64);
    return decryptFileWithAES(encryptedContent, aesKey);
}

function calculateSHA256(file) {
    // TODO: 这里要改成支持校验，
    // return "12345";
    const md = forge.md.sha256.create();
    md.update(file);
    return md.digest().toHex();  // 返回十六进制格式的哈希值
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
    const files = event.target.files;
    for (let file of files) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const base64Image = e.target.result;
            addImagePreview(base64Image);
        };
        reader.readAsDataURL(file);
    }
});

function setFileDisplay(fileName, base64File) {
    const filePreview = document.getElementById('image-preview'); // 使用相同的预览区域
    filePreview.innerHTML = `<p>文件名: ${fileName}</p>`;
    filePreview.dataset.base64 = base64File;
    filePreview.dataset.fileName = fileName;
    document.getElementById('input-message').focus();
}

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
                        addImagePreview(base64File);  // 使用新的预览函数
                    } else {
                        if (isValidBase64File(base64File)) {
                            addFilePreview(fileName, base64File);  // 使用新的预览函数
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


function generateUniqueId() {
    return 'image_' + Math.random().toString(36).substr(2, 9);
}

function sendImageMessage(imagePrefix, downloadUrl, imageHash, aesKey) {
    const encryptedMessage = encryptMessage(JSON.stringify({
        imageInfo: {
            url: downloadUrl,
            sha256: imageHash,
            aesKey: forge.util.encode64(aesKey), // 用Base64编码AES密钥
            imagePrefix: imagePrefix
        },
        change_nickname: g_myNickName
    }));
    g_websocket.send(JSON.stringify({
        action: 'send_message',
        channel_id: g_hashed_channel_id,
        encrypted_message: encryptedMessage
    }));
}

async function innerSendImageBase64(base64Image) {
    const [imagePrefix, content] = base64Image.split(','); // 获取Base64编码的图片数据
    const aesKey = forge.random.getBytesSync(32); // 生成一个新的AES密钥
    const encryptedImage = encryptFileWithAES(atob(content), aesKey); // 用AES密钥加密图片
    const downloadUrl = await uploadFileToServer(encryptedImage); // 上传加密后的图片
    const imageHash = calculateSHA256(atob(content)); // 计算原始图片的哈希值

    sendImageMessage(imagePrefix, downloadUrl, imageHash, aesKey); // 发送图片消息
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

function sendPreviews() {
    const previewsContainer = document.getElementById('previews-container');
    const previewItems = previewsContainer.getElementsByClassName('preview-item');

    for (let previewElem of previewItems) {
        if (previewElem.dataset.fileName) {
            // 发送文件
            appendFileToChatBox(g_myNickName, getShortHash(getPublicKeyHash(g_myPublicKey)), previewElem.dataset.base64, previewElem.dataset.fileName, getColorFromSHA256(getPublicKeyHash(g_myPublicKey)));
            innerSendFileBase64(previewElem.dataset.base64, previewElem.dataset.fileName);
        } else if (previewElem.dataset.base64) {
            // 发送图片
            innerSendImageBase64(previewElem.dataset.base64);
        }
    }

    // 清空预览区域
    previewsContainer.innerHTML = '';
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
        sendPreviews();
    });

    // 监听按 Enter 键发送消息和 Shift+Enter 换行
    document.getElementById('input-message').addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();  // 阻止默认的 Enter 行为
            sendMessage();
            sendPreviews();
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

let g_heartbeatInterval = undefined;

// 开始定时发送心跳
function startHeartbeat() {
    console.log(`startHeartbeat`);
    // 每隔1秒发送一次心跳
    g_heartbeatInterval = setInterval(function () {
        sendHeartbeat();
    }, 1000);
}

// 停止定时发送心跳
function stopHeartbeat() {
    console.log(`inside stopHeartbeat`);
    if (g_heartbeatInterval) {
        clearInterval(g_heartbeatInterval);
        g_heartbeatInterval = null;
    }
}

// 发送心跳消息
function sendHeartbeat() {
    console.log(`发送心跳包。`);
    if (g_websocket && g_websocket.readyState === WebSocket.OPEN) {
        const message = JSON.stringify({ action: 'heartbeat' });
        g_websocket.send(message);
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
        // 一旦WebSocket连接打开，开始定时发送心跳
        startHeartbeat();
        sendHeartbeat();
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
        stopHeartbeat(); // 停止心跳
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

// function sendHeartbeat() {
//     const message = JSON.stringify({ action: 'heartbeat' });
//     g_websocket.send(message);
// }

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
            // console.log(messageJson);
            const innerMessageJson = JSON.parse(messageJson.message);
            handleIncomeMessageJsonFields(publicKeyHash, innerMessageJson);
        } catch (e) {
            console.error('Failed to parse JSON message:', e);
        }
    } else {
        console.error('Signature verification failed');
    }
}

async function handleFileDownload(nickname, fingerprint, fingerprintColor, event, url, fileName, expectedHash, messageElem, aesKeyBase64) {
    try {
        const fileContent = await downloadAndDecryptFile(url, aesKeyBase64); // 下载并解密文件
        const base64File = fileContent; // 这里的base64File其实是解密后的文件内容
        if (calculateSHA256(base64File) !== expectedHash) {
            throw new Error("File hash does not match expected hash.");
        }

        messageElem.innerHTML = ''; // 清空消息元素内容

        const fileLink = document.createElement('a');
        fileLink.href = `data:application/octet-stream;base64,${btoa(fileContent)}`; // 创建下载链接
        // fileLink.href = `${fileContent}`;
        fileLink.download = fileName;
        fileLink.textContent = `${fingerprint}(${nickname})${fileName}`;
        fileLink.style.color = '#007bff';
        fileLink.style.textDecoration = 'underline';

        messageElem.appendChild(fileLink);
    } catch (error) {
        console.error("File verification failed:", error);
        alert("文件校验失败，无法加载文件。");
    }
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return window.btoa(binary);
}


function appendFileLinkToChatBox(nickname, fingerprint, downloadUrl, fileName, fingerprintColor, fileHash, aesKeyBase64) {
    const chatBox = document.getElementById('chat-box');
    const messageElem = document.createElement('p');

    const nicknameText = document.createTextNode(`${nickname} `);
    const fingerprintSpan = document.createElement('span');
    fingerprintSpan.textContent = fingerprint;
    fingerprintSpan.style.color = fingerprintColor;
    fingerprintSpan.classList.add("message-text");

    const fileLink = document.createElement('a'); // 使用<a>元素作为文件名和点击加载的容器
    fileLink.href = "#"; // 使用锚点防止页面跳转
    fileLink.textContent = `${fileName} （点击加载）`;
    fileLink.style.color = '#007bff';
    fileLink.style.textDecoration = 'underline';

    // 将文件下载和验证处理程序绑定到<a>元素的点击事件
    fileLink.addEventListener('click', function (event) {
        event.preventDefault(); // 阻止默认行为
        handleFileDownload(nickname, fingerprint, fingerprintColor, event, downloadUrl, fileName, fileHash, messageElem, aesKeyBase64);
    });

    messageElem.appendChild(fingerprintSpan);
    messageElem.appendChild(nicknameText);
    messageElem.appendChild(fileLink);
    chatBox.appendChild(messageElem);
    chatBox.scrollTop = chatBox.scrollHeight;
}

async function downloadAndDecryptImage(imagePrefix, url, aesKeyBase64, expectedHash, callback) {
    try {
        const encryptedContent = await fetch(url).then(response => response.text());
        const aesKey = forge.util.decode64(aesKeyBase64);
        const decryptedImage = decryptFileWithAES(encryptedContent, aesKey);
        const imageBase64 = btoa(decryptedImage);

        if (calculateSHA256(decryptedImage) !== expectedHash) {
            throw new Error("Image hash does not match expected hash.");
        }
        callback(`${imagePrefix},${imageBase64}`);
    } catch (error) {
        console.error("Error downloading or decrypting image:", error);
    }
}



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
            }
            else if (key === 'base64File') {
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                appendFileToChatBox(nickname, fingerprint, json[key], json.fileName, fingerprintColor);
            } else if (key === 'fileInfo') { // Assuming 'url' is the key used for the download URL in the message
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                appendFileLinkToChatBox(nickname, fingerprint, json['fileInfo']['url'], json['fileInfo']['fileName'], fingerprintColor, json['fileInfo']['sha256'], json['fileInfo']['aesKey']);
            } else if (json.hasOwnProperty('imageInfo')) {
                const imageInfo = json['imageInfo'];
                const nickname = getNickname(publicKeyHash);
                const fingerprint = getShortHash(publicKeyHash);
                const fingerprintColor = getColorFromSHA256(publicKeyHash);
                const downloadUrl = imageInfo['url'];
                const expectedHash = imageInfo['sha256'];
                const aesKeyBase64 = imageInfo['aesKey'];
                const imagePrefix = imageInfo['imagePrefix'];

                downloadAndDecryptImage(imagePrefix, downloadUrl, aesKeyBase64, expectedHash, (decryptedImageBase64) => {
                    appendImageToChatBox(nickname, fingerprint, decryptedImageBase64, fingerprintColor);
                });
            }

            else {
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
