import random
import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


with open("pri.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

data_to_send = {}

data = {
    "wireless module": "802.11b/g/n 2.4 GHz",
    "module": "Health Monitor",
    "OS": "Tizen",
    "auth": "fingerprint identification",
    "app name": 'smart blood pressure',
    "average_power_consumption": "0.06w/h"}

registration = {
    "patient name": "Jim",
    "patient id": "30070008",
    "device name": 'Health Monitor',
    "device id": "30070008_01",
    "function": 'blood pressure monitor'
}


def register():
    url = 'http://192.168.1.104:5000/eHealth/register'
    req = requests.post(url=url, json=registration)
    resp = req.text
    print(resp)


def smartwatch_app():
    url = 'http://192.168.1.104:5000/gateway/transfer'
    blood_pressure = round(random.uniform(60, 120))
    str_blood_pressure = str(blood_pressure)
    data["blood pressure"] = str_blood_pressure
    data["device number"] = '30070008_01'
    data_to_send["data"] = data
    signature = private_key.sign(
        bytes(str(data), 'utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512())
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

