import random
import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


with open("private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

data_to_send = {}

data = {
    "wireless module": "802.11b/g/n 2.4 GHz",
    "module": "eHealth watch",
    "OS": "wear os",
    "auth": "2FA",
    "app name": 'sugar monitor',
    "average_power_consumption": "0.2w/h"}

registration = {
    "patient name": "Tom",
    "patient id": "30070007",
    "device name": 'eHealth watch',
    "device id": "30070007_01",
    "function": "blood sugar monitor"
}

def register():
    url = 'http://192.168.1.104:5000/eHealth/register'
    req = requests.post(url=url, json=registration)
    resp = req.text
    print(resp)

def smartwatch_app():
    url = 'http://192.168.1.104:5000/gateway/transfer'
    blood_sugar = round(random.uniform(110, 160), 2)
    data["blood sugar"] = blood_sugar
    data["device number"] = '30070007_01'
    data_to_send["data"] = data
    signature = private_key.sign(
        bytes(str(data), 'utf-8'),
        ec.ECDSA(hashes.SHA256()))
    data_to_send["signature"] = signature.hex()
    req = requests.post(url=url, json=data_to_send)
    resp = req.text
    print(resp)


if __name__ == '__main__':
    scheduler = BlockingScheduler()
    scheduler.add_job(smartwatch_app, 'cron', second='*/3', hour='*')
    try:
        while True:
            option = input("What do you want to do? \n1.Monitor Start \n2.Register\n")
            if option == "1":
                scheduler.start()
            elif option == "2":
                register()
    except KeyboardInterrupt:
        print("eHealth watch shuts down")