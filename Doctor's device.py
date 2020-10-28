import requests
import json
from PIL import Image
import io
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


data = {
    'OS': 'windows10',
    'browser': 'Google Chrome(version83.0.4103.97)',
    'app': 'eHealth monitor(web application)',
    'WAF': 'Mod security',
    'security protocol': 'TLS1.2-RSA-AES-256SHA'
}


with open("private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )


def query_patient_device():
    url = 'http://127.0.0.1:5000/eHealth/query/patient_device/'
    resp = requests.get(url=url)
    for x in json.loads(resp.text)['processed_datalist']:
        print(x)


def retrieve(device):
    url = 'http://127.0.0.1:5000/eHealth/query/data/' + device
    resp = requests.get(url=url)
    for x in json.loads(resp.text)['processed_datalist']:
        retrieve_processed_data(device + "&" + x)


def retrieve_processed_data(data_name):
    url = 'http://127.0.0.1:5000/eHealth/doctor/retrieve/processed_data/' + data_name
    data_to_send = {}
    signature = private_key.sign(
        bytes(str(data), 'utf-8'), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    data_to_send['data'] = data
    data_to_send['signature'] = signature.hex()
    resp = requests.get(url=url, json=data_to_send)
    resp_data = resp.content
    if resp_data == b'It does not exist':
        print('It does not exist')
    else:
        img = Image.open(io.BytesIO(resp_data))
        img.show()


def get_capture_sec_metadata(time_label):
    url = "http://127.0.0.1:5000/eHealth/retrieve/capture/security_metadata/" + time_label
    resp = requests.get(url=url)
    print(resp.text)


def get_register_sec_metadata(time_label):
    url = "http://127.0.0.1:5000/eHealth/retrieve/register/security_metadata/" + time_label
    resp = requests.get(url=url)
    print(resp.text)


def get_datapropagate_sec_metadata(time_label):
    url = "http://127.0.0.1:5000/eHealth/retrieve/data_propagate/security_metadata/" + time_label
    resp = requests.get(url=url)
    print(resp.text)


def get_dataprocess_sec_metadata(time_label):
    url = "http://127.0.0.1:5000/eHealth/retrieve/data_process/security_metadata/" + time_label
    resp = requests.get(url=url)
    print(resp.text)


def get_patient_access_sec_metadata(time_label):
    url = "http://127.0.0.1:5000/eHealth/retrieve/patient_access/security_metadata/" + time_label
    resp = requests.get(url=url)
    print(resp.text)


def get_doctor_access_sec_metadata(time_label):
    url = "http://127.0.0.1:5000/eHealth/retrieve/doctor_access/security_metadata/" + time_label
    resp = requests.get(url=url)
    print(resp.text)


def untrusted_check(device_id):
    url = "http://127.0.0.1:5000/eHealth/doctor/security_check/" + device_id
    resp = requests.get(url=url)
    print(resp.text)


try:
    while True:
        option = input("Welcome to use eHealth monitor web application. "
                       "\nWhat do you want to do? \n1.Query \n2.Retrieve \n3.Get Security Metadata(For Auditor Use)\n4.Trust Check\n")
        if option == '1':
            print('Your are responsible for')
            query_patient_device()



        elif option == '2':
            device_name = input("Please enter the device name:\n")
            retrieve(device_name)

        elif option == '3':
            data_name = input("Please enter the time label of the data:\n")
            activity = input("Which activity's security metadata do you want to check?"
                             "\n1. register\n2. capture\n3. propagate\n4. data process\n5. doctor access\n")
            if activity == '1':
                get_register_sec_metadata(data_name)
            elif activity == '2':
                get_capture_sec_metadata(data_name)
            elif activity == '3':
                get_datapropagate_sec_metadata(data_name)
            elif activity == '4':
                get_dataprocess_sec_metadata(data_name)
            elif activity == '5':
                get_doctor_access_sec_metadata(data_name)

        elif option == '4':
            device_id = input("Please enter the device id you want to check\n")
            untrusted_check(device_id)


except KeyboardInterrupt:
    print("Quit")