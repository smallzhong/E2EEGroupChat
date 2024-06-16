#  E2EEGroupChat

[中文README](README_CN.MD) 

E2EEGroupChat is a real-time end-to-end encrypted (E2EE) group chat application based on WebSocket. Using RSA and AES encryption technologies, it ensures that messages are not exposed to the server or any third parties during transmission. **The design philosophy of this application considers the server as a potentially malicious middleman**. Therefore, the server does not store any plaintext or keys; it only forwards encrypted messages. Even if the server is compromised and becomes a malicious middleman, the attackers cannot eavesdrop on any user messages. **For detailed encryption process, see the swim lane diagram: https://chat.0f31.com/swim-lane-en.html**.

## Project Preview

You can try it out at https://chat.0f31.com/.

## Features

- **End-to-End Encryption**: Uses RSA and AES encryption to ensure that only the sender and receiver can decrypt messages.
- **Forward and Backward Secrecy**: When users join or leave a channel, new AES keys are generated. This means a **user can only see messages from the time they join the channel until they leave**. Messages sent before joining or after leaving cannot be decrypted due to different AES keys. Therefore, if two people are having a private conversation and suddenly a third person joins the chat room, they can immediately stop chatting and switch to another channel, preventing the newcomer from reading any of their messages.
- **Real-Time Communication**: Implements low-latency message transmission via WebSocket.
- **Online User List**: Displays the current online users in real-time.
- **Simple and User-Friendly Interface**: Responsive design that adapts to various devices.

## Tech Stack

- Frontend: HTML, CSS, JavaScript, Bootstrap
- Encryption Library: node-forge
- Real-Time Communication: WebSocket

## Usage Instructions

1. Open https://chat.0f31.com/ and follow the prompts to join a channel. You can choose to join a channel with a random name of your own, or join preset channels like `lounge` for chatting. The channel name is encrypted for the server, and the server can only see a hash of the channel. Even if the server is compromised by attackers, they cannot know or join the user's channel.
2. Upon successful connection, the application will generate an RSA key pair and send the public key to the server.
3. The server will forward the public keys of other users, and the frontend will store these public keys.
4. Users enter messages and send them; the frontend encrypts messages using the AES key, and the server only forwards encrypted messages.
5. When a new user joins or a user leaves, the frontend will generate a new AES key and distribute it encrypted to other users.
6. **No cookies are used, and closing the window will result in the loss of all chat messages.**

## Security Mechanisms

- **RSA Encryption**: Used to encrypt AES keys, ensuring secure key transmission.
- **AES Encryption**: Used to encrypt message content, ensuring messages are not intercepted during transmission.
- **Dynamic Key Updates**: New AES keys are generated when users join or leave a channel, preventing new users from decrypting previous messages and old users from decrypting subsequent messages.

## Acknowledgements

- Special thanks to [rao2357](https://github.com/rao2357) and [zouxianyu](https://github.com/zouxianyu) for their contributions to the cryptographic protocol design of the project.

## Contribution Guidelines

We welcome suggestions and improvements to the E2EEGroupChat project. Please follow these steps to contribute:

1. Fork the repository.

2. Create a new branch:

   ```
   git checkout -b feature-branch
   ```

3. Commit your changes:

   ```
   git commit -m "Describe your changes"
   ```

4. Push to the branch:

   ```
   git push origin feature-branch
   ```

5. Create a Pull Request.

## License

This project is licensed under the MIT License.