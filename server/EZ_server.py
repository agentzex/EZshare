import pymongo
import hashlib
from flask import Flask, request, jsonify, make_response, send_from_directory, redirect, url_for
import socket
import os
from random import randint, choice
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import json
import threading
import udp_server

printable = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

SERVER_HOSTNAME = socket.gethostname()
SERVER_IP = socket.gethostbyname(SERVER_HOSTNAME)
PID = str(os.getpid())


print("HTTP Server started on: " + SERVER_HOSTNAME + " with IP: " + SERVER_IP + "\nPID: " + PID)
app = Flask(__name__)
app.secret_key = "ujc63jDjm"


with open("pub.key", "r") as file:
    public_key = file.read()
with open("private.key", "r") as file:
    private_key = file.read()

public_key_obj = RSA.importKey(public_key)
private_key_obj = RSA.importKey(private_key)



def edit_user(current_user_name, new_user_name):
    ret = users.update_one({"user_name": current_user_name}, {"$set": {"user_name": new_user_name}})
    if ret.modified_count > 0:
        print "record updated successfully"
    else:
        print "couldn't update user"


def delete_user(user_name):
    ret = users.delete_one({"user_name": user_name})
    if ret.deleted_count > 0 :
        print "user deleted"
    else:
        print "user couldn't be deleted"


@app.route('/pre_connect')
def pre_connection():
    user_id = str(request.args.get("user_id"))
    if users.find_one({"user_id": user_id}):
        print "user already found in DB!"
    else:
        user_id = create_user_id()
        try:
            users.insert_one({"user_id": user_id})
            print "user added successfully"
        except Exception, e:
            print "Error: " + str(e)
            return send_http_response('0', str(e))
    return send_http_response('1', {"UID": user_id, "public_key": public_key})


@app.route('/connect', methods=['POST'])
def request_connection():
    if not request.method == 'POST':
        return send_http_response('0')
    user_ip = request.remote_addr
    user_id = str(request.form.get("user_id"))
    if not user_id:
        return send_http_response('0')
    client_aes_key = str(request.form.get("key"))
    if not client_aes_key:
        return send_http_response('0')
    client_iv = str(request.form.get("iv"))
    if not client_iv:
        return send_http_response('0')

    if users.find_one({"user_id": user_id}):
        print "user found in dB"
        ret = users.update_one({"user_id": user_id}, {"$set": {"connected": True}})
        if ret.matched_count > 0:
            if ret.modified_count > 0:
                print user_id + " is now connected!"
            else:
                print user_id + " is already connected!"
        else:
            print "couldn't connect user"
            return send_http_response('0')
    else:
        return send_http_response('0')
    ret = users.update_one({"user_id": user_id}, {"$set": {"user_ip": user_ip}})
    if ret == None:
        return send_http_response('0')
    password = create_password(user_id)
    if not password:
        return send_http_response('0')
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    client_aes_key_wrapped = base64.b64decode(client_aes_key)
    client_aes_key = cipher_rsa.decrypt(client_aes_key_wrapped)
    client_iv_wrapped = base64.b64decode(client_iv)
    client_iv = cipher_rsa.decrypt(client_iv_wrapped)

    ret = users.update_one({"user_id": user_id}, {"$set": {"aes_b64": base64.b64encode(client_aes_key), "iv": base64.b64encode(client_iv)}})
    if ret.modified_count > 0:
        print "aes_key and iv updated"
    else:
        return send_http_response('0')
    ret = users.update_one({"user_id": user_id}, {"$set": {"password": password}})
    if ret.modified_count > 0:
        print "password updated"
        aes_cipher = generate_cipher(client_aes_key, client_iv)
        return send_http_response('1', {"user_password": password}, aes_cipher)
    return send_http_response('0')


@app.route('/disconnect')
def request_disconnection():
    user_id = request.args.get("user_id")
    if not user_id:
        print "must have user_id"
        return send_http_response('0')
    ret = users.update_one({"user_id": user_id}, {"$set": {"connected": False}})
    if ret.modified_count > 0:
        print user_id + " disconnected!"
        return send_http_response('1')
    else:
        print "couldn't disconnect user"
        return send_http_response('0')



@app.route('/session_with_user', methods=['POST'])
def session_with_user():
    if not request.method == 'POST':
        return send_http_response('0')
    user_id = request.form.get("user_id")
    if not user_id:
        print "must have user_id"
        return send_http_response('0')
    user = users.find_one({"user_id": user_id})
    if not user:
        return send_http_response('0')

    target_user_id = request.form.get("target_user_id")
    if not target_user_id:
        print "must have target user_id"
        return send_http_response('0')
    target_user_password = request.form.get("target_user_password")
    if not target_user_password:
        print "must have target user password"
        return send_http_response('0')

    #checking target details exists
    client_aes_cipher = generate_cipher_b64(user["aes_b64"], user["iv"])
    target_user_id = decrypt_payload(client_aes_cipher, base64.b64decode(target_user_id))
    target_user_password = decrypt_payload(client_aes_cipher, base64.b64decode(target_user_password))
    target_user = check_connected(target_user_id)
    if not target_user:
        return send_http_response('0')
    target_status = target_user["connected"]
    if target_status == False:
        print "target user not connected"
        return send_http_response('0', "target user not connected")
    if target_user["password"] != target_user_password:
        return send_http_response('0')
    # return send_http_response('1', {"user_ip": target_user["user_ip"]}, client_aes_cipher)
    user_ip = users.find_one({"user_id": user_id})
    user_ip = user_ip["user_ip"]
    target_user_ip = users.find_one({"user_id": target_user_id})
    target_user_ip = target_user_ip["user_ip"]

    print "Starting UDP server for IP: " + user_ip + " and IP: " + target_user_ip
    t = threading.Thread(target=udp_server.main, args=(user_ip, target_user_ip))
    t.start()
    return send_http_response('1')


def send_http_response(status, extra_data=None, aes_cipher=None):
    #1 == ok,  0 == error
    if not extra_data:
        response = make_response(jsonify(status=status, extra_data=""))
    elif not aes_cipher:
        response = make_response(jsonify(status=status, extra_data=extra_data))
    else:
        extra_data = json.dumps(extra_data)
        encrypted_msg = base64.b64encode(aes_cipher.encrypt(extra_data))
        response = make_response(jsonify(status=status, extra_data=encrypted_msg))
    return response


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_CFB, iv)


def generate_cipher_b64(aes_key, iv):
    aes_key = base64.b64decode(aes_key)
    iv = base64.b64decode(iv)
    return AES.new(aes_key, AES.MODE_CFB, iv)


def create_password(user_id):
    ret = users.find_one({"user_id": user_id})
    if ret:
        password_list = []
        for i in range(6):
            x = choice(printable)
            password_list.append(x)
        password = "".join(password_list)
        return password
    else:
        print "user id not found in DB!"
        return None


def create_user_id():
    user_id = randint(0, 999999)
    user_id = "%06d" % user_id
    ret = users.find_one({"user_id": user_id})
    while ret != None:
        user_id = randint(0, 999999)
        user_id = "%06d" % user_id
        ret = users.find_one({"user_id": user_id})
    return user_id



def check_connected(id):
    ret = users.find_one({"user_id": id})
    if ret:
        return ret
    else:
        print "user id not found in DB!"
        return None



if __name__ == '__main__':
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["EZShare"]
    users = mydb["users"]
    # create_password("c753f714-1dcc-4a30-acc1-9c9d97586d30")

    salt = "ujc63jDjm"
    app.run(host="0.0.0.0", port=80)
