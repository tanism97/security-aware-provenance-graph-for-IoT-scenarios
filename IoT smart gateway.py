from flask import Flask
from flask import request
import requests
import cryptography
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as pad


app = Flask(__name__)
blood_sugar = []
blood_pressure = []
metadata_list = []
metadata_list2 = []
security_check_list = []
security_check_list2 = []
data = {}
data2 = {}
gateway_metadata = {}


with open("public.pem", "rb") as key_file:
    public_key1 = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )


with open("public2.pem", "rb") as key_file:
    public_key2 = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )


def aes_cbc_256(data):
    # an example symmetric encryption
    key2 = b'=\xd0\xa8x\x00\x9f\xfdI\xaa\x8f\x82\xec\x9b\x1di\x19\xf4CK\xdb\xfd$r\x9f\xab\x04uy@\xd6\\\x1a'
    iv2 = b'\xaeCHg\xc7h\x83\xd9-SS\xe6\xc8\xac#\xe6'
    padder = pad.PKCS7(256).padder()
    padded_data = padder.update(bytes(str(data), 'utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key2), modes.CBC(iv2), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct


# check the metadata get from IoT device
def iot_metadata_check(datalist):
    if (datalist.count(datalist[0]) == len(datalist)) is True:
        return datalist[0]
    else:
        return "security metadata changed"


@app.route('/gateway/transfer', methods=['POST'])
def data_process():
    received_data = request.json
    if received_data["data"]["device number"] == "30070007_01":
        signature = bytes.fromhex(received_data["signature"])
        single_data = received_data["data"]
        try:
            public_key1.verify(signature, bytes(str(single_data), 'utf-8'), ec.ECDSA(hashes.SHA256()))
            blood_sugar.append(received_data["data"]['blood sugar'])
        except cryptography.exceptions.InvalidSignature:
            blood_sugar.append(received_data["data"]['blood sugar'])
            security_check_list.append("Warning")
        del received_data["data"]['blood sugar']
        del received_data["data"]["device number"]
        del received_data['signature']
        metadata_list.append(received_data["data"])
        if len(blood_sugar) == len(metadata_list) == 10:
            security_metadata = iot_metadata_check(metadata_list)
            data["device number"] = "30070007_01"
            data['security metadata'] = security_metadata
            data['blood sugar'] = blood_sugar
            if len(security_check_list) != 0:
                gateway_metadata['gateway name'] = 'smart gateway X'
                gateway_metadata["IoT device signature verification"] = "EC-prime256v1-SHA256 verify fail"
                gateway_metadata["encryption method"] = "AES-256-CBC"
                gateway_metadata["security protocol"] = "TLS1.2-RSA-AES-256SHA"
                data['gateway metadata'] = gateway_metadata
            else:
                gateway_metadata['gateway name'] = 'smart gateway X'
                gateway_metadata["IoT device signature verification"] = "EC-prime256v1-SHA256 verified"
                gateway_metadata["encryption method"] = "AES-256-CBC"
                gateway_metadata["security protocol"] = "TLS1.2-RSA-AES-256SHA"
                data['gateway metadata'] = gateway_metadata
            secret_data = aes_cbc_256(data)
            url = 'http://127.0.0.1:5000/eHealth/data_process'
            req = requests.post(url=url, data=secret_data)
            resp = req.text
            gateway_metadata.clear()
            data.clear()
            blood_sugar.clear()
            metadata_list.clear()
            security_check_list.clear()
            return resp

    elif received_data["data"]["device number"] == "30070008_01":
        signature = bytes.fromhex(received_data["signature"])
        single_data = received_data["data"]
        try:
            public_key2.verify(signature, bytes(str(single_data), 'utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512())
            blood_pressure.append(received_data["data"]['blood pressure'])
        except cryptography.exceptions.InvalidSignature:
            blood_pressure.append(received_data["data"]['blood pressure'])
            security_check_list2.append("Warning")
        del received_data["data"]['blood pressure']
        del received_data["data"]["device number"]
        del received_data['signature']
        metadata_list2.append(received_data["data"])
        if len(blood_pressure) == len(metadata_list2) == 10:
            security_metadata = iot_metadata_check(metadata_list2)
            data2["device number"] = "30070008_01"
            data2['security metadata'] = security_metadata
            data2['blood pressure'] = blood_pressure
            if len(security_check_list2) != 0:
                gateway_metadata['gateway name'] = 'smart gateway X'
                gateway_metadata["IoT device signature verification"] = "RSA2048-SHA512 verify fail"
                gateway_metadata["encryption method"] = "AES-256-CBC"
                gateway_metadata["security protocol"] = "TLS1.2-RSA-AES-256SHA"
                data2['gateway metadata'] = gateway_metadata
            else:
                gateway_metadata['gateway name'] = 'smart gateway X'
                gateway_metadata["IoT device signature verification"] = "RSA2048-SHA512 verified"
                gateway_metadata["encryption method"] = "AES-256-CBC"
                gateway_metadata["security protocol"] = "TLS1.2-RSA-AES-256SHA"
                data2['gateway metadata'] = gateway_metadata
            secret_data = aes_cbc_256(data2)
            url = 'http://127.0.0.1:5000/eHealth/data_process'
            req = requests.post(url=url, data=secret_data)
            resp = req.text
            gateway_metadata.clear()
            data2.clear()
            blood_pressure.clear()
            metadata_list2.clear()
            security_check_list2.clear()
            return resp

    else:
        return "Configure and Register First"
    return "OK"


@app.route('/eHealth/register', methods=['POST'])
def transfer():
    received_data = request.json
    url = 'http://127.0.0.1:5000/eHealth/register'
    req = requests.post(url=url, json=received_data)
    resp = req.text
    return resp

@app.route('/', methods=['GET'])
def hello_world():
    return "hello world"


if __name__ == '__main__':
    app.run()