import urllib.request
import urllib.parse
import json
import os

file_path = "/Volumes/Appending Storage/0617/test-upload.txt"
url_base = "http://localhost:8787"
token = "admin"

print(f"Reading file: {file_path}")
with open(file_path, 'rb') as f:
    file_content = f.read()

# 1. Init Upload
print("Initializing upload...")
init_data = json.dumps({"filename": "test-upload.txt", "contentType": "text/plain"}).encode('utf-8')
req = urllib.request.Request(
    f"{url_base}/api/upload-init",
    data=init_data,
    headers={"Content-Type": "application/json", "Authorization": token},
    method="POST"
)
with urllib.request.urlopen(req) as res:
    init_res = json.loads(res.read().decode('utf-8'))
    print("Init Res:", init_res)
    upload_id = init_res["uploadId"]
    key = init_res["key"]

# 2. Upload Part 1
print("Uploading Part 1...")
req = urllib.request.Request(
    f"{url_base}/api/upload-part?key={urllib.parse.quote(key)}&uploadId={upload_id}&partNumber=1",
    data=file_content,
    headers={"Authorization": token},
    method="POST"
)
with urllib.request.urlopen(req) as res:
    part_res = json.loads(res.read().decode('utf-8'))
    print("Part Res:", part_res)
    etag = part_res["etag"]

# 3. Complete Upload
print("Completing upload...")
complete_data = json.dumps({"parts": [{"partNumber": 1, "etag": etag}]}).encode('utf-8')
req = urllib.request.Request(
    f"{url_base}/api/upload-complete?key={urllib.parse.quote(key)}&uploadId={upload_id}",
    data=complete_data,
    headers={"Content-Type": "application/json", "Authorization": token},
    method="POST"
)
with urllib.request.urlopen(req) as res:
    complete_res = json.loads(res.read().decode('utf-8'))
    print("Complete Res:", complete_res)

print("Upload test successful!")
