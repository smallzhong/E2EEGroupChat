package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// 允许跨域请求，在生产环境中需要更严格的配置
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

//	type Channels struct {
//		ChannelID string
//		ClientInfo
//	}
var Channels = make(map[string][]ClientInfo, 10)

const HEARTBEAT_INTERVAL int = 3

type ClientInfo struct {
	Connect            *websocket.Conn
	ChannelID          string
	PublickKey         string
	PublickKeyHash     string
	ChannelIDSignature string
}
type SocketMessage struct {
	Action              string `json:"action"`
	EncryptedMessage    string `json:"encrypted_message"`
	PublicKey           string `json:"public_key"`
	PublicKeyHash       string `json:"public_key_hash"`
	EncryptedKey        string `json:"encrypted_key"`
	ChannelID           string `json:"channel_id"`
	ChannelIDSignature  string `json:"channel_id_signature"`
	SenderPublicKeyHash string `json:"sender_public_key_hash"`
	Nonce               string `json:"nonce"`
	TimeStamp           int64  `json:"timestamp"`
	Signature           string `json:"signature"`
}

//	func handleWebSocket(conn net.Conn) {
//		client_info := ClientInfo{Connect: websocket, PublickKey: None, PublickKeyHash: None}
//		reader := bufio.NewReader(conn)
//		reader.
//	}
func LoadPublicKeyFromPEM(pemData string) (interface{}, error) {
	// 将 PEM 数据解码为 pem.Block
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}

	// 解析公钥
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}
func PrintfChannel() {
	for key, clients := range Channels {
		log.Printf("频道%s共有%d 个用户: \n", key, len(clients))
		// 遍历每个 channel 对应的客户端信息切片
		for _, client := range clients {
			log.Printf("  公钥哈希: %s\n", client.PublickKeyHash)
		}
	}
}
func SendPublicKey(channel_id string) {
	clientInfos := Channels[channel_id]
	for i, clientInfo := range clientInfos {
		for j, otherclientInfo := range clientInfos {
			if i != j {
				message := SocketMessage{
					Action:        "receive_public_key",
					PublicKey:     otherclientInfo.PublickKey,
					PublicKeyHash: otherclientInfo.PublickKeyHash,
					// # 这里加一个字段，hmac(channel_id, 自己公钥签名)。
					// # 接收的时候如果这个值不对，说明这个人不知道channel_id的真实值。
					// # 服务器能知道别人用的这个签名，但是那是别人的公钥，自己的公钥的签名无从得知，那signature字段就是非法的，还是过不去校验。
					// # 这里要从全局列表取。
					ChannelIDSignature: otherclientInfo.ChannelIDSignature,
				}
				// messagejson,err:=json.Marshal(message)
				// if err!=nil{
				// 	log.Printf("消息json失败")
				// }
				clientInfo.Connect.WriteJSON(message)

			}
		}
	}
	//随机让人生成密钥

	randomInt := rand.Intn(len(Channels[channel_id]))
	message := SocketMessage{Action: "generate_aes_key"}
	Channels[channel_id][randomInt].Connect.WriteJSON(message)
}
func HashPublicKey(publicKeyPEM string) (string, error) {
	// 解码 PEM 格式的公钥
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM data")
	}

	// 解析公钥
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	// 将公钥转换为 DER 格式
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key to DER: %w", err)
	}

	// 计算 SHA-256 哈希
	hash := sha256.Sum256(der)

	// 将哈希结果转换为十六进制字符串
	digest := hex.EncodeToString(hash[:])

	// 打印哈希值
	fmt.Println(digest)

	return digest, nil
}
func removeElement(slice []ClientInfo, index int) []ClientInfo {
	// 检查索引是否越界
	if index < 0 || index >= len(slice) {
		return slice
	}
	// 从切片中移除指定位置的元素
	return append(slice[:index], slice[index+1:]...)
}
func join_channel(websocketdata SocketMessage, client_info *ClientInfo) {
	var err error
	PrintfChannel()
	channels_id := websocketdata.ChannelID

	public_keystr := websocketdata.PublicKey

	client_info.PublickKey = public_keystr
	client_info.PublickKeyHash, err = HashPublicKey(public_keystr)
	client_info.ChannelIDSignature = websocketdata.ChannelIDSignature
	client_info.ChannelID = channels_id
	if err != nil {
		log.Printf("hash公钥失败")
	}
	log.Printf("当前用户%s想加入频道%s", websocketdata.PublicKeyHash, channels_id)
	_, exists := Channels[channels_id]
	if exists {
		Channels[channels_id] = append(Channels[channels_id], *client_info)
		SendPublicKey(channels_id)
	} else {
		Channels[channels_id] = []ClientInfo{*client_info}
	}

}
func send_key(websocketdata SocketMessage) {
	channel_id := websocketdata.ChannelID
	encrypted_key := websocketdata.EncryptedKey
	public_key_hash := websocketdata.PublicKeyHash
	sender_public_key_hash := websocketdata.SenderPublicKeyHash
	nonce := websocketdata.Nonce
	timestamp := websocketdata.TimeStamp
	signature := websocketdata.Signature
	for _, client_info := range Channels[channel_id] {
		if client_info.PublickKeyHash == public_key_hash {
			message := SocketMessage{Action: "receive_key", EncryptedKey: encrypted_key,
				PublicKeyHash:       public_key_hash,
				SenderPublicKeyHash: sender_public_key_hash,
				Nonce:               nonce, TimeStamp: timestamp,
				Signature:          signature,
				ChannelIDSignature: websocketdata.ChannelIDSignature}
			client_info.Connect.WriteJSON(message)
		}
	}
}
func send_message(websocketdata SocketMessage, client_info ClientInfo) {
	channel_id := websocketdata.ChannelID
	encrypted_message := websocketdata.EncryptedMessage
	for _, client := range Channels[channel_id] {
		if client.Connect != client_info.Connect {
			message := SocketMessage{Action: "receive_message", EncryptedMessage: encrypted_message, PublicKeyHash: client_info.PublickKeyHash}
			client.Connect.WriteJSON(message)
		}
	}
}
func handle_client_disconnect(client_info ClientInfo) {
	for i, client := range Channels[client_info.ChannelID] {
		if client.PublickKeyHash == client_info.PublickKeyHash {
			client_info.Connect.Close()
			Channels[client_info.ChannelID] = removeElement(Channels[client_info.ChannelID], i)
			disconnectMessage := SocketMessage{Action: "member_left", PublicKeyHash: client.PublickKeyHash}
			for _, otherclient := range Channels[client_info.ChannelID] {
				otherclient.Connect.WriteJSON(disconnectMessage)

			}
			if len(Channels[client_info.ChannelID]) > 0 {
				SendPublicKey(client.ChannelID)
			}
			log.Printf("当前频道用户量：%d", len(Channels[client_info.ChannelID]))
			break
		}
	}
}
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 将HTTP连接升级为WebSocket连接
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket升级失败:", err)
		return
	}
	client_info := ClientInfo{Connect: conn}
	// defer conn.Close()

	for {
		// 读取客户端发送的消息
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println("读取消息出错:", err)
			log.Printf("self.handle_client_disconnect(client_info)")
			handle_client_disconnect(client_info)
			break
		}
		if messageType == 8 {
			log.Printf("self.handle_client_disconnect(client_info)")
			handle_client_disconnect(client_info)
		}

		// log.Printf("收到消息: %s\n", string(p))
		var socketMessage SocketMessage
		json.Unmarshal(p, &socketMessage)
		if socketMessage.Action != "" {
			if socketMessage.Action == "join" {
				join_channel(socketMessage, &client_info)
			} else if socketMessage.Action == "send_key" {
				send_key(socketMessage)
			} else if socketMessage.Action == "send_message" {
				send_message(socketMessage, client_info)
			}
		}
		if socketMessage.Action != "heartbeat" {
			log.Printf("收到消息: %s\n", string(p))
		}
		// // 向客户端发送响应消息
		// err = conn.WriteMessage(messageType, p)
		// if err != nil {
		// 	log.Println("发送消息出错:", err)
		// 	break
		// }
	}
}
func main() {
	http.HandleFunc("/", handleWebSocket)
	log.Println("WebSocket服务器启动，监听端口: 8765")
	// 启动HTTP服务器
	// certFile := "chat.yuchu.space.pem"
	// keyFile := "chat.yuchu.space.key"
	// if err := http.ListenAndServeTLS(":8765", certFile, keyFile, nil); err != nil {
	// 	log.Fatal("服务器启动失败:", err)
	// }
	if err := http.ListenAndServe(":8765", nil); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}
