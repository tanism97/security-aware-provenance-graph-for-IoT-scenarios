import os
import time
from flask import Flask
from flask import request
from flask import jsonify
from flask import send_file
import matplotlib.pyplot as plt
from neo4j import GraphDatabase
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
# neo4j drive
#driver = GraphDatabase.driver("neo4j+s://www.iothealthprovenance.com:7687", auth=("neo4j", "i-0c304992c401a8d37"))
driver = GraphDatabase.driver("neo4j://localhost:7687", auth=("neo4j", "boyutan"))

standard_appsecurity_metadata = {'OS': 'windows10', 'browser': 'Google Chrome(version83.0.4103.97)',
                                 'app': 'eHealth monitor(web application)', 'WAF': 'Mod security',
                                 'Dr identity verification': 'RSA1024-SHA256 verified', 'security protocol': 'TLS-RSA-AES-256SHA'}


register_info = {}


with open("drpublic.pem", "rb") as key_file:
    public_key_dr = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

def decryption(data):
    backend = default_backend()
    key = b'=\xd0\xa8x\x00\x9f\xfdI\xaa\x8f\x82\xec\x9b\x1di\x19\xf4CK\xdb\xfd$r\x9f\xab\x04uy@\xd6\\\x1a'
    iv = b'\xaeCHg\xc7h\x83\xd9-SS\xe6\xc8\xac#\xe6'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    pt = decryptor.update(data) + decryptor.finalize()
    unpadder = pad.PKCS7(256).unpadder()
    plaintext = eval((unpadder.update(pt) + unpadder.finalize()).decode('utf-8'))
    return plaintext


# time label
def save_time():
    ts = time.time()
    lt = time.localtime(ts)
    now = time.strftime("%Y-%m-%d_%H:%M:%S", lt)
    return now


def wasGeneratedBy(tx, entity, activity, time):
    tx.run("MERGE (a:Entity {entity: $entity, time_label: $time}) "
           "MERGE (b:Activity {activity: $activity, time_label: $time}) "
           "MERGE (a)-[:wasGeneratedBy]->(b)",
           entity=entity, activity=activity, time=time)


def wasAssociatedWith(tx, activity, agent, time1, time2):
    tx.run("MERGE (b:Activity {activity: $activity, time_label: $time1}) "
           "MERGE (c:Agent {agent: $agent, time_label: $time2}) "
           "MERGE (b)-[:wasAssociatedWith]->(c)",
           activity=activity, agent=agent, time1=time1, time2=time2)


def wasInformedBy(tx, activity1, activity2, time1, time2):
    tx.run("MERGE (a:Activity {activity: $activity1, time_label: $time1}) "
           "MERGE (b:Activity {activity: $activity2, time_label: $time2}) "
           "MERGE (a)-[:wasInformedBy]->(b)",
           activity1=activity1, activity2=activity2, time1=time1, time2=time2)


def wasDerivedFrom(tx, entity1, entity2, time1, time2):
    tx.run("MERGE (a:Entity {entity: $entity1, time_label: $time1}) "
           "MERGE (b:Entity {entity: $entity2, time_label: $time2}) "
           "MERGE (a)-[:wasDerivedFrom]->(b)",
           entity1=entity1, entity2=entity2, time1=time1, time2=time2)


def wasProvedBy(tx, activity, security_metadata, time):
    tx.run("MERGE (a:Activity {activity: $activity, time_label: $time}) "
           "MERGE (b:SecurityMetadata {security_metadata: $SecurityMetadata, time_label: $time}) "
           "MERGE (a)-[:wasProvedBy]->(b)",
           activity=activity, SecurityMetadata=security_metadata, time=time)


def print_metadata(tx, activity, time_label):
    for record in tx.run("MATCH (a)-[:wasProvedBy]->(b) WHERE a.activity = $activity AND a.time_label=$time_label "
                         "RETURN b.security_metadata", activity=activity, time_label=time_label):
        return record["b.security_metadata"]


def print_metadata2(tx, activity, time_label):
    record_dic = {}
    x = 0
    for record in tx.run("MATCH (a)-[:wasProvedBy]->(b) WHERE a.activity = $activity AND a.time_label=$time_label "
                         "RETURN b.security_metadata", activity=activity, time_label=time_label):
        x = x + 1
        record_dic["access" + str(x)] = record["b.security_metadata"]

    return record_dic


# check the metadata get from IoT device
def iot_metadata_check(datalist):
    if (datalist.count(datalist[0]) == len(datalist)) is True:
        return datalist[0]
    else:
        return "metadata changed"


@app.route('/eHealth/register', methods=['POST'])
def store_info():
    received_data = request.json
    if received_data['device id'] in register_info:
        return "This device has registered before!"
    else:
        register_info[received_data['device id']] = received_data
        register_info[received_data['device id']]['register time'] = save_time()
        os.mkdir('processed_data/' + received_data['device id'] + "/")
        return "Register finished!"
#/home/ubuntu/flaskproject/

@app.route('/eHealth/data_process', methods=['POST'])
def data_process():
    ct = request.data
    received_data = decryption(ct)
    device_id = received_data['device number']
    if device_id in register_info:
        if register_info[device_id]['function'] == 'blood sugar monitor':
            security_metadata_ac2 = received_data['security metadata']
            blood_sugar = received_data['blood sugar']
            security_metadata_ac3 = received_data['gateway metadata']
            gateway_name = received_data['gateway metadata']['gateway name']
            del security_metadata_ac3['gateway name']
            patient_name = register_info[device_id]['patient name']
            patient_id = register_info[device_id]['patient id']
            device_name = register_info[device_id]['device name']
            register_time = register_info[device_id]['register time']
            time_label = device_id + '&' + save_time()
            plt.plot(blood_sugar)
            plt.xlabel("time(s)")
            plt.ylabel("blood sugar(mg/dL)")
            plt.savefig('processed_data/' + device_id + "/" + save_time() + '.jpg')
            plt.close()
            with driver.session() as session:
                session.write_transaction(wasGeneratedBy,
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ",raw_data",
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          time_label)
                session.write_transaction(wasGeneratedBy,
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ",raw_data",
                                          device_name + " captures raw data from " + patient_name, time_label)
                session.write_transaction(wasAssociatedWith,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "sensor:" + device_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "patient:" + patient_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "cloud service:eHealth analysis", time_label, time_label)
                session.write_transaction(wasAssociatedWith, device_name + " captures raw data from " + patient_name,
                                          "patient:" + patient_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith, device_name + " captures raw data from " + patient_name,
                                          "sensor:" + device_name, time_label, time_label)

                session.write_transaction(wasInformedBy, device_name + " captures raw data from " + patient_name,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          time_label,
                                          time_label)
                session.write_transaction(wasProvedBy,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "registered time:" + register_time + ",service provider: AWS",
                                          time_label)
                session.write_transaction(wasProvedBy, device_name + " captures raw data from " + patient_name,
                                          str(security_metadata_ac2),
                                          time_label)

                session.write_transaction(wasInformedBy, "raw data aggregate then propagate to the cloud via gateway",
                                          device_name + " captures raw data from " + patient_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data aggregate then propagate to the cloud via gateway",
                                          "sensor:" + device_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data aggregate then propagate to the cloud via gateway",
                                          'gateway:' + gateway_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data aggregate then propagate to the cloud via gateway",
                                          "cloud service:eHealth analysis", time_label, time_label)

                session.write_transaction(wasInformedBy, "raw data is processed and stored in the cloud",
                                          "raw data aggregate then propagate to the cloud via gateway", time_label,
                                          time_label)
                session.write_transaction(wasGeneratedBy,
                        "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ',' + time_label[12:] + '.jpg',
                                          "raw data is processed and stored in the cloud", time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data is processed and stored in the cloud",
                                          "cloud service:eHealth analysis", time_label, time_label)
                session.write_transaction(wasProvedBy, "raw data aggregate then propagate to the cloud via gateway",
                                          str(security_metadata_ac3), time_label)
                session.write_transaction(wasProvedBy, "raw data is processed and stored in the cloud",
                                          "TLS-RSA-AES-256SHA, Provider AWS, Unencrypted in the cloud ", time_label)
                session.write_transaction(wasDerivedFrom,
                        "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ',' + time_label[12:] + '.jpg',
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ",raw_data",
                                          time_label,
                                          time_label)

        elif register_info[device_id]['function'] == 'blood pressure monitor':
            security_metadata_ac2 = received_data['security metadata']
            blood_pressure = received_data["blood pressure"]
            security_metadata_ac3 = received_data['gateway metadata']
            gateway_name = received_data['gateway metadata']['gateway name']
            del security_metadata_ac3['gateway name']
            patient_name = register_info[device_id]['patient name']
            patient_id = register_info[device_id]['patient id']
            device_name = register_info[device_id]['device name']
            register_time = register_info[device_id]['register time']
            time_label = device_id + '&' + save_time()
            plt.plot(blood_pressure)
            plt.xlabel("time(s)")
            plt.ylabel("blood pressure(mmHg)")
            plt.savefig('processed_data/' + device_id + "/" + save_time() + '.jpg')
            plt.close()
            with driver.session() as session:
                session.write_transaction(wasGeneratedBy,
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ",raw_data",
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          time_label)
                session.write_transaction(wasGeneratedBy,
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ",raw_data",
                                          device_name + " captures raw data from " + patient_name, time_label)
                session.write_transaction(wasAssociatedWith,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "sensor:" + device_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "patient:" + patient_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "cloud service:eHealth analysis", time_label, time_label)
                session.write_transaction(wasAssociatedWith, device_name + " captures raw data from " + patient_name,
                                          "patient:" + patient_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith, device_name + " captures raw data from " + patient_name,
                                          "sensor:" + device_name, time_label, time_label)

                session.write_transaction(wasInformedBy, device_name + " captures raw data from " + patient_name,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          time_label,
                                          time_label)
                session.write_transaction(wasProvedBy,
                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                          "registered time:" + register_time + ",service provider: AWS",
                                          time_label)
                session.write_transaction(wasProvedBy, device_name + " captures raw data from " + patient_name,
                                          str(security_metadata_ac2),
                                          time_label)

                session.write_transaction(wasInformedBy, "raw data aggregate then propagate to the cloud via gateway",
                                          device_name + " captures raw data from " + patient_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data aggregate then propagate to the cloud via gateway",
                                          "sensor:" + device_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data aggregate then propagate to the cloud via gateway",
                                          'gateway:' + gateway_name, time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data aggregate then propagate to the cloud via gateway",
                                          "cloud service:eHealth analysis", time_label, time_label)

                session.write_transaction(wasInformedBy, "raw data is processed and stored in the cloud",
                                          "raw data aggregate then propagate to the cloud via gateway", time_label,
                                          time_label)
                session.write_transaction(wasGeneratedBy,"patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ',' + time_label[12:] + '.jpg',
                                          "raw data is processed and stored in the cloud", time_label)
                session.write_transaction(wasAssociatedWith,
                                          "raw data is processed and stored in the cloud",
                                          "cloud service:eHealth analysis", time_label, time_label)
                session.write_transaction(wasProvedBy, "raw data aggregate then propagate to the cloud via gateway",
                                          str(security_metadata_ac3), time_label)
                session.write_transaction(wasProvedBy, "raw data is processed and stored in the cloud",
                                          "TLS-RSA-AES-256SHA, Provider AWS, Unencrypted in the cloud ", time_label)
                session.write_transaction(wasDerivedFrom,"patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ',' + time_label[12:] + '.jpg',
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ",raw_data",
                                          time_label,
                                          time_label)
    else:
        return "You need to register"
    return "OK"


@app.route('/eHealth/query/patient_device/', methods=['GET'])
def patient_device_query():
    data_list = os.listdir('processed_data/')
    data = {"processed_datalist": data_list}
    return jsonify(data)


@app.route('/eHealth/query/data/<name>', methods=['GET'])
def query(name):
    data_list = os.listdir('processed_data/' + name)
    data = {"processed_datalist": data_list}
    return jsonify(data)


@app.route('/eHealth/doctor/retrieve/processed_data/<dataname>', methods=['GET'])
def doctor_image_retrieve(dataname):
    received_data = request.json
    signature = bytes.fromhex(received_data["signature"])
    security_metadata = received_data['data']
    try:
        public_key_dr.verify(signature,  bytes(str(security_metadata), 'utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        security_metadata['Dr identity verification'] = 'RSA1024-SHA256 verified'
        security_metadata['security protocol'] = 'TLS-RSA-AES-256SHA'
        security_metadata['retrieve_time'] = save_time()
        name = dataname[0:11] + "/" + dataname[12:]
        filename = 'processed_data/' + name
        if os.path.exists(filename):
            device_id = name[0:11]
            time_label = device_id + '&' + name[12:-4]
            patient_id = register_info[device_id]['patient id']
            with driver.session() as session:
                session.write_transaction(wasGeneratedBy,
                                          "patient_id:" + patient_id + ",patient_sensor_id:" + device_id + ",processed data:" + name[
                                                                                                                                12:] + ",doctor_id:6002",
                                          "doctor accesses data from cloud using his device", time_label)
                session.write_transaction(wasInformedBy,
                                          "doctor accesses data from cloud using his device",
                                          "raw data is processed and stored in the cloud", time_label, time_label)
                session.write_transaction(wasDerivedFrom,
                                          "patient_id:" + patient_id + ",patient_sensor_id:" + device_id + ",processed data:" + name[
                                                                                                                                12:] + ",doctor_id:6002",
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ',' + name[
                                                                                                                 12:-4] + '.jpg',
                                          time_label, time_label)
                session.write_transaction(wasProvedBy, "doctor accesses data from cloud using his device",
                                          str(security_metadata), time_label)
                session.write_transaction(wasAssociatedWith,
                                          "doctor accesses data from cloud using his device",
                                          "doctor device:doctors laptop(in hospital)", time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "doctor accesses data from cloud using his device",
                                          "cloud service:eHealth analysis", time_label, time_label)

            return send_file(filename)
        else:
            return "It does not exist"
    except cryptography.exceptions.InvalidSignature:
        security_metadata['Dr identity verification'] = 'RSA1024-SHA256 verify fail'
        security_metadata['security protocol'] = 'TLS-RSA-AES-256SHA'
        security_metadata['retrieve_time'] = save_time()
        name = dataname[0:11] + "/" + dataname[12:]
        filename = 'processed_data/' + name
        if os.path.exists(filename):
            device_id = name[0:11]
            time_label = device_id + '&' + name[12:-4]
            patient_id = register_info[device_id]['patient id']
            with driver.session() as session:
                session.write_transaction(wasGeneratedBy,
                                          "patient_id:" + patient_id + ",patient_sensor_id:" + device_id + ",processed data:" + name[
                                                                                                                                12:] + ",doctor_id:6002",
                                          "doctor accesses data from cloud using his device", time_label)
                session.write_transaction(wasInformedBy,
                                          "doctor accesses data from cloud using his device",
                                          "raw data is processed and stored in the cloud", time_label, time_label)
                session.write_transaction(wasDerivedFrom,
                                          "patient_id:" + patient_id + ",patient_sensor_id:" + device_id + ",processed data:" + name[
                                                                                                                                12:] + ",doctor_id:6002",
                                          "patient_id:" + patient_id + ',patient_sensor_id:' + device_id + ',' + name[
                                                                                                                 12:-4] + '.jpg',
                                          time_label, time_label)
                session.write_transaction(wasProvedBy, "doctor accesses data from cloud using his device",
                                          str(security_metadata), time_label)
                session.write_transaction(wasAssociatedWith,
                                          "doctor accesses data from cloud using his device",
                                          "doctor device:doctors laptop(in hospital)", time_label, time_label)
                session.write_transaction(wasAssociatedWith,
                                          "doctor accesses data from cloud using his device",
                                          "cloud service:eHealth analysis", time_label, time_label)
            return "Identity Verify Fail"
        else:
            return "It does not exist"




@app.route('/eHealth/retrieve/register/security_metadata/<time_label>', methods=['GET'])
def print_register_metadata(time_label):
    device_id = time_label[0:11]
    device_name = register_info[device_id]['device name']
    patient_name = register_info[device_id]['patient name']
    security_metadata = driver.session().read_transaction(print_metadata,
                                                          patient_name + " along with the " + device_name + " are registered in cloud",
                                                          time_label)
    return jsonify(security_metadata)


@app.route('/eHealth/retrieve/capture/security_metadata/<time_label>', methods=['GET'])
def print_capture_metadata(time_label):
    device_id = time_label[0:11]
    device_name = register_info[device_id]['device name']
    patient_name = register_info[device_id]['patient name']
    security_metadata = driver.session().read_transaction(print_metadata,
                                                          device_name + " captures raw data from " + patient_name,
                                                          time_label)
    return jsonify(security_metadata)


@app.route('/eHealth/retrieve/data_propagate/security_metadata/<time_label>', methods=['GET'])
def print_data_propagate_metadata(time_label):
    security_metadata = driver.session().read_transaction(print_metadata,
                                                          "raw data aggregate then propagate to the cloud via gateway",
                                                          time_label)
    return jsonify(security_metadata)


@app.route('/eHealth/retrieve/data_process/security_metadata/<time_label>', methods=['GET'])
def print_data_process_metadata(time_label):
    security_metadata = driver.session().read_transaction(print_metadata,
                                                          "raw data is processed and stored in the cloud",
                                                          time_label)
    return jsonify(security_metadata)


@app.route('/eHealth/retrieve/patient_access/security_metadata/<time_label>', methods=['GET'])
def print_patient_access_metadata2(time_label):
    security_metadata = driver.session().read_transaction(print_metadata2,
                                                          "patient accesses data from cloud using his smartphone",
                                                          time_label)
    return security_metadata


@app.route('/eHealth/retrieve/doctor_access/security_metadata/<time_label>', methods=['GET'])
def print_doctor_access_metadata2(time_label):
    security_metadata = driver.session().read_transaction(print_metadata2,
                                                          "doctor accesses data from cloud using his device",
                                                          time_label)
    return security_metadata


def application_security_check(data):
    for value in data.values():
        dic = eval(value)
        del dic['retrieve_time']
        if dic != standard_appsecurity_metadata:
            return 'untrusted'



def trust_check(time_label):
    location = ""
    device_id = time_label[0:11]
    device_name = register_info[device_id]['device name']
    patient_name = register_info[device_id]['patient name']
    security_metadata_sensing = driver.session().read_transaction(print_metadata,
                                                          device_name + " captures raw data from " + patient_name,
                                                          time_label)
    security_metadata_propagate = driver.session().read_transaction(print_metadata,
                                                          "raw data aggregate then propagate to the cloud via gateway",
                                                          time_label)
    security_metadata_application = driver.session().read_transaction(print_metadata2,
                                                          "doctor accesses data from cloud using his device",
                                                          time_label)
    if security_metadata_sensing == "security metadata changed":
        location += " activity2"
    if "verify fail" in eval(security_metadata_propagate)['IoT device signature verification'] or eval(security_metadata_propagate)['encryption method'] != "AES-256-CBC":
        location += " activity3"
    if application_security_check(security_metadata_application) == "untrusted":
        location += " activity5"
    if location != "":
        return "untrusted" + location
    else:
        return "trusted"


@app.route('/eHealth/doctor/security_check/<device_id>', methods=['GET'])
def security_check(device_id):
    untrusted_list = []
    data_list = os.listdir('processed_data/' + device_id)
    for x in data_list:
        result = trust_check(device_id + "&" + x[:-4])
        if 'untrusted' in result:
            untrusted_list.append(x + '(' + result[10:] + ')')
    if len(untrusted_list) == 0:
        return "All the data from this device can be trusted"
    else:
        return "Untrusted data:" + str(untrusted_list) + "\nIf you have any question, please consult the auditor."


if __name__ == '__main__':
    try:
        app.run()
    except KeyboardInterrupt:
        print("exit")