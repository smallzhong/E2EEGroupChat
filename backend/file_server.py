from flask import Flask, request, send_from_directory
from flask_cors import CORS
import os
import uuid
import threading
import time


def LOG(msg):
    print(msg)


g_file_max_time = 12 * 3600  # 12小时
g_check_gap = 360  # 多久检查一次，暂时6分钟

app = Flask(__name__)

# 允许的CORS域名
cors_origins = ["http://127.0.0.1", "http://localhost", "https://chat.0f31.com", "http://chat.0f31.com",
                "https://ws.0f31.com", "http://ws.0f31.com"]

# 初始化CORS支持
CORS(app, origins=cors_origins)

# 创建一个目录来存储上传的文件
UPLOAD_DIRECTORY = "/path/to/the/uploads"

if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        # 生成一个随机的文件名
        filename = str(uuid.uuid4())
        file.save(os.path.join(UPLOAD_DIRECTORY, filename))
        return {'url': f'/download/{filename}'}


@app.route('/download/<path:path>')
def download_file(path):
    return send_from_directory(UPLOAD_DIRECTORY, path, as_attachment=True)


def delete_old_files():
    while True:
        LOG('inside delete_old_files')
        now = time.time()
        for filename in os.listdir(UPLOAD_DIRECTORY):
            file_path = os.path.join(UPLOAD_DIRECTORY, filename)
            if os.path.isfile(file_path):
                file_age = now - os.path.getmtime(file_path)
                if file_age > g_file_max_time:
                    LOG(f'删除{file_path}')
                    os.remove(file_path)
        time.sleep(g_check_gap)  # 每小时检查一次


if __name__ == "__main__":
    # 启动定时任务线程
    cleaner_thread = threading.Thread(target=delete_old_files, daemon=True)
    cleaner_thread.start()
    app.run(port=8000)
