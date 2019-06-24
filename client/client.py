import requests
import json
import os
from Crypto.Cipher import AES
from Crypto import Random
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import udp_client
import threading


# SERVER_IP = "192.168.1.93"
SERVER_IP = "18.219.69.4"


def generate_key():
    aes_key = Random.new().read(32)
    iv = Random.new().read(AES.block_size)
    return aes_key, iv


def generate_cipher(aes_key, iv):
    aes_key = base64.b64decode(aes_key)
    iv = base64.b64decode(iv)
    return AES.new(aes_key, AES.MODE_CFB, iv)


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def encrypt_payload(cipher, plain_payload):
    return base64.b64encode(cipher.encrypt(plain_payload))


def read_details():
    if not os.path.exists("uid"):
        return {}
    with open("uid", "r") as file:
        r = file.read()
        return json.loads(r)


def disconnect():
    user_details = read_details()
    if not user_details:
        print "couldn't find user id locally"
        return
    uid = user_details["UID"]
    r = requests.get("http://" + SERVER_IP + "/disconnect?user_id=" + uid).text
    r = json.loads(r)
    status = r["status"]
    if status == '0':
        print "server response: couldn't disconnect"
    else:
        print "server response: disconnected successfully"


def pre_connect():
    user_details = read_details()
    if not user_details:
        r = requests.get("http://" + SERVER_IP + "/pre_connect?user_id=").text
    else:
        uid = user_details["UID"]
        r = requests.get("http://" + SERVER_IP + "/pre_connect?user_id=" + uid).text

    r = json.loads(r)
    status = r["status"]
    if status == '0':
        return None
    response = r["extra_data"]
    public_key = response["public_key"]
    user_id = response["UID"]
    aes_key, iv = generate_key()
    user_details["aes_key"] = base64.b64encode(aes_key)
    user_details["iv"] = base64.b64encode(iv)
    user_details["UID"] = user_id
    with open("uid", "w") as file:
        file.write(json.dumps(user_details))
    public_key_obj = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj.publickey())
    enc_aes_key = base64.b64encode(cipher.encrypt(aes_key))
    enc_iv = base64.b64encode(cipher.encrypt(iv))
    return enc_aes_key, enc_iv


def connect(enc_aes_key, enc_iv):
    user_details = read_details()
    if not user_details:
        return None
    else:
        uid = user_details["UID"]
        r = requests.post("http://" + SERVER_IP +"/connect", data={"user_id": uid, "key": enc_aes_key, "iv": enc_iv}).text
    r = json.loads(r)
    status = r["status"]
    if status == '0':
        return None
    response = r["extra_data"]
    if response:
        decoded = base64.b64decode(response)
        aes_cipher = generate_cipher(user_details["aes_key"], user_details["iv"])
        decoded = decrypt_payload(aes_cipher, decoded)
        decoded = json.loads(decoded)
        password = decoded["user_password"]
        user_details["User_Password"] = password
        with open("uid", "w") as file:
            file.write(json.dumps(user_details))
        print "UID: " + user_details["UID"] + "\nUser Password: " + password
    else:
        print "error response from server"


def session_with_user(target_user_id, target_user_password):
    user_details = read_details()
    if not user_details:
        return False
    aes_cipher = generate_cipher(user_details["aes_key"], user_details["iv"])
    target_user_id = encrypt_payload(aes_cipher, target_user_id)
    target_user_password = encrypt_payload(aes_cipher, target_user_password)
    r = requests.post("http://" + SERVER_IP + "/session_with_user", data={"user_id": user_details["UID"], "target_user_id": target_user_id, "target_user_password": target_user_password}).text
    r = json.loads(r)
    status = r["status"]
    if status == '0':
        return False
    return True
    # response = r["extra_data"]
    # if response:
    #     decoded = base64.b64decode(response)
    #     decoded = decrypt_payload(aes_cipher, decoded)
    #     decoded = json.loads(decoded)
    #     user_ip = decoded["user_ip"]
    #     print "target user ip: " + user_ip


if __name__ == '__main__':
    # disconnect()
    enc_aes_key, enc_iv = pre_connect()
    if not enc_aes_key or not enc_iv:
        exit(-1)
    connect(enc_aes_key, enc_iv)
    # if session_with_user("108551", "GiIHKq"):
    #     udp_client.main(SERVER_IP, 9999)
