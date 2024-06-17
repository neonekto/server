import socket
import threading
import queue
import hashlib as hash
from peewee import *
from datetime import datetime, timedelta
import secrets
import string
import smtplib
import requests
import json
from scipy.spatial import distance
from playhouse.postgres_ext import ArrayField
import numpy as np
import pytz
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, ParameterFormat,  load_pem_public_key, load_pem_parameters
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


port = 5050
ip_server = '192.168.1.106'
address = (ip_server, port)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(address)

parameters = dh.generate_parameters(generator=2, key_size=2048)
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()


connect = PostgresqlDatabase('app', user='server', password='server', host='127.0.0.1', port=5432)

class BaseModel(Model):
    class Meta:
        database = connect

class Users(BaseModel):
    id_user = IntegerField(column_name='id_user', primary_key=True)    
    login = TextField(column_name='login', null=False)
    password = TextField(column_name='password', null=False)
    e_mail = TextField(column_name='e_mail', null=False)
    salt = TextField(column_name='salt', null=False)

    class Meta:
        table_name = 'users'

class SystemInfo(BaseModel):
    id_system = IntegerField(column_name='id_system', primary_key=True)
    user_id = ForeignKeyField(Users, column_name='user_id', null=False)
    ip_address = TextField(column_name='ip_address', null=False)
    mac_address = TextField(column_name='mac_address', null=False)
    pc_name = TextField(column_name='pc_name', null=False)
    os_name = TextField(column_name='os', null=False)
    arch = TextField(column_name='arch', null=False)
    country = TextField(column_name='country', null=False)
    city = TextField(column_name='city', null=False)
    
    class Meta:
        table_name = 'system_info'

class FaceInfo(BaseModel):
    id_face = IntegerField(column_name='id_face', primary_key=True)
    user_id = ForeignKeyField(Users, column_name='user_id', null=False)
    vector = ArrayField(IntegerField, dimensions=1, column_name='vector', null=False)

    class Meta:
        table_name = 'face_info'

class OtpInfo(BaseModel):
    id_otp = IntegerField(column_name='id_otp', primary_key=True)
    user_id = ForeignKeyField(Users, column_name='user_id', null=False)
    time = DateTimeField(column_name='time', null=False)
    value = TextField(column_name='value', null=False)

    class Meta:
        table_name = 'otp_info'

class TempPassword(BaseModel):
    id_temp_pass = IntegerField(column_name='id_temp_pass', primary_key=True)
    user_id = ForeignKeyField(Users, column_name='user_id', null=False)
    count_attempts_pass = IntegerField(column_name='count_attempts_pass', null=False)

    class Meta:
        table_name = 'temp_password'
        
class TempOtp(BaseModel):
    id_temp_otp = IntegerField(column_name='id_temp_otp', primary_key=True)
    user_id = ForeignKeyField(Users, column_name='user_id', null=False)
    count_attempts_otp = IntegerField(column_name='count_attempts_otp', null=False)

    class Meta:
        table_name = 'temp_otp'


def recv(conn):    
    recv_msg = conn.recv(1024)
    msg = recv_msg.decode('utf8')    
    return msg

def send(msg, conn):
    conn.send(msg.encode('utf8'))
    
def encrypt(message, key):
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, message.encode('utf8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf8')

def decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    nonce = data[:12]
    ciphertext = data[12:]
    chacha = ChaCha20Poly1305(key)
    message = chacha.decrypt(nonce, ciphertext, None)
    if "|" in message.decode('utf8'):
        msg = message.decode('utf8').split("|")
    else:
        msg = message.decode('utf8')
    return msg

def generate_salt():
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(secrets.choice(letters_and_digits) for i in range(6))

class User():

    def __init__(self, login, password, conn):
        self.login = login
        self.password = hash.sha512(password.encode('utf8')).hexdigest()
        self.conn = conn


    def autentification(self):
        query = Users.select().where((Users.login == self.login) & (Users.password == self.password))
        auth_user = query.dicts().execute()        
        if len(auth_user) == 0:
            return False
        else:
            self.id = int(auth_user[0]['id_user'])
            return True  


    def check_otp(self, msg):
        count_attempts = TempOtp.select().where(TempOtp.user_id == self.id)
        user_count_attempts = count_attempts.dicts().execute()
        if int(user_count_attempts[0]['count_attempts_otp']) == 3:
            return "close"
        else:
            query_otp_info = OtpInfo.select().where(OtpInfo.user_id == self.id).limit(1).order_by(OtpInfo.time.desc())
            info_otp = query_otp_info.dicts().execute()
            if info_otp[0]['value'] == msg :
                query_update_count_attempts_otp = TempOtp.update(count_attempts_otp=0).where(TempOtp.user_id == self.id)
                query_update_count_attempts_otp.execute()
                return True
            else:
                query_update_count_attempts_otp = TempOtp.update(count_attempts_otp=int(user_count_attempts[0]['count_attempts_otp']) + 1).where(TempOtp.user_id == self.id)
                query_update_count_attempts_otp.execute()
                return False


    def check_bio(self, msg):
        if msg == "":
            return False
        else:
            query_face_vector = FaceInfo.select().where(FaceInfo.user_id == self.id)
            face_vector = query_face_vector.dicts().execute()
            msg_vector = np.array(list(msg.replace("[", "").replace(", ", "").replace("]", "").replace(" ", "").replace("\n", "")), dtype=int)
            try:
                hamming_dist = distance.hamming(np.array(face_vector[0]['vector'], dtype=int), msg_vector)
                if hamming_dist < 5:
                    return True
                else:
                    return False
            except:
                return False


    def change_mail(self, msg):
        query_update_mail = Users.update(e_mail=msg).where(Users.id_user == self.id)
        query_update_mail.execute()
                
    
def send_email(message, to_addr):
        server = 'smtp.mail.ru'
        user = 'example_api@mail.ru'
        password = 'QyFhZ4nNivS9wn5GviTc'

        sender = 'example_api@mail.ru'
        subject = 'OTP-code'
        body = "\r\n".join((f"From: {user}", f"To: {to_addr}", 
               f"Subject: {subject}", message))

        mail = smtplib.SMTP_SSL(server)
        mail.login(user, password)
        mail.sendmail(sender, to_addr, body.encode('utf8'))
        mail.quit()

def generate_otp():
    return ''.join(secrets.choice(string.digits) for i in range(6))


def handle_client(conn, q, addr, derived_key):
    connected = True
    while connected:
        #try:
            encrypted_message = recv(conn)
            msg = decrypt(encrypted_message, derived_key)
            #msg = recv(conn)
            if msg:
                q.put((conn, msg))
                user_login_pass = ""
                
                if msg[0] == "log":
                    query_id_from_sys = SystemInfo.select().where(SystemInfo.ip_address == addr[0])
                    id_from_sys = query_id_from_sys.dicts().execute()
                    query_count_attempts = TempPassword.select().where(TempPassword.user_id == id_from_sys[0]['user_id'])
                    user_count_attempts = query_count_attempts.dicts().execute()
                    if int(user_count_attempts[0]['count_attempts_pass']) == 3:
                        encrypted_response = encrypt("400", derived_key)
                        send(encrypted_response, conn)
                        #send('400', conn)
                        conn.close()
                    else:
                        login = msg[1]
                        passwd = msg[2]                      
                        login_salt = Users.select().where(Users.login == login)
                        user_salt = login_salt.dicts().execute()                                   
                        pass_with_salt = passwd + user_salt[0]['salt']
                        user = User(login, pass_with_salt, conn)
                        if user.autentification():                            
                            system_info = msg[3].split(",")
                            query_update_count_attempts_pass = TempPassword.update(count_attempts_pass=0).where(TempPassword.user_id == user.id)
                            query_update_count_attempts_pass.execute()
                            query_info_pc_user = SystemInfo.select().where(SystemInfo.user_id == user.id)
                            info_pc_user = query_info_pc_user.dicts().execute()
                            #ip_api = "http://ip-api.com/json/" + addr[0]
                            ip_api = "http://ip-api.com/json/212.21.0.44"
                            response_ip_api = json.loads(requests.get(ip_api).text)
                            time_info = datetime.now(pytz.timezone('Asia/Yekaterinburg'))
                            time_start = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0).replace(tzinfo=pytz.timezone('Asia/Yekaterinburg'))
                            time_end = datetime.now().replace(hour=18, minute=0, second=0, microsecond=0).replace(tzinfo=pytz.timezone('Asia/Yekaterinburg'))
                            if info_pc_user[0]['country'] != response_ip_api['country'] or info_pc_user[0]['city'] != response_ip_api['city']:
                                encrypted_response = encrypt_message(derived_key, "200")
                                send(encrypted_response, conn)
                                #send("200", conn)
                            elif not (time_info >= time_start and time_info <= time_end):
                                encrypted_response = encrypt("200", derived_key)
                                send(encrypted_response, conn)
                                #send("200", conn)
                            elif info_pc_user[0]['ip_address'] != addr[0] or info_pc_user[0]['mac_address'] != system_info[0] or info_pc_user[0]['pc_name'] != system_info[1] or info_pc_user[0]['os_name'] != system_info[2] or info_pc_user[0]['arch'] != system_info[3]:
                                encrypted_response = encrypt("200", derived_key)
                                send(encrypted_response, conn)
                                #send("200", conn)
                            else:
                                encrypted_response = encrypt("100", derived_key)
                                send(encrypted_response, conn)
                                #send("100", conn)
                            query_user_mail = Users.select().where((Users.login == user.login) & (Users.password == user.password))                            
                            user_mail = query_user_mail.dicts().execute()
                            otp_code = generate_otp()
                            query = OtpInfo.select().limit(1).order_by(OtpInfo.id_otp.desc())
                            last_id_otp = query.dicts().execute()
                            datetime_info = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if len(last_id_otp) == 0:
                                new_otp = OtpInfo.create(id_otp=1, user_id=user.id, time=datetime_info, value=otp_code)
                                new_otp.save()
                            else:
                                new_otp = OtpInfo.create(id_otp=int(last_id_otp[0]['id_otp']) + 1, user_id=user.id, time=datetime_info, value=otp_code)                                
                                new_otp.save()
                            send_email(otp_code, user_mail[0]['e_mail'])
                        else:
                            query_user = Users.select().where(Users.login == user.login)
                            user_id = query_user.dicts().execute()
                            query_user_id_temp = TempPassword.select().where(TempPassword.user_id == user_id[0]['id_user'])
                            user_id_temp = query_user_id_temp.dicts().execute()
                            if len(user_id_temp) == 0:
                                 pass
                            else:
                                query_update_count_attempts_pass = TempPassword.update(count_attempts_pass=int(user_count_attempts[0]['count_attempts_pass']) + 1).where(TempPassword.user_id == user_id[0]['id_user'])
                                query_update_count_attempts_pass.execute()
                            encrypted_response = encrypt("300", derived_key)
                            send(encrypted_response, conn)
                            #send("300", conn)
                            
                elif msg[0] == "otp":
                    if user.check_otp(msg[1]) == "close":
                        encrypted_response = encrypt("400", derived_key)
                        send(encrypted_response, conn)
                        #send("400", conn)
                        conn.close()
                    elif user.check_otp(msg[1]): 
                        encrypted_response = encrypt("100", derived_key)
                        send(encrypted_response, conn)
                        #send("100", conn) 
                    else:
                        encrypted_response = encrypt("300", derived_key)
                        send(encrypted_response, conn)
                        #send("300", conn)
                        
                elif msg[0] == "face":
                    if user.check_bio(msg[1]):
                        encrypted_response = encrypt("100", derived_key)
                        send(encrypted_response, conn)
                        #send("100", conn)
                    else:
                        encrypted_response = encrypt("300", derived_key)
                        send(encrypted_response, conn)
                        #send("300", conn)
                        
                elif msg[0] == "reg":                 
                    salt_new_user = generate_salt()
                    data_reg = msg[4].split(",")
                    query_login_exist = Users.select().where(Users.login == msg[1])
                    login_exist = query_login_exist.dicts().execute() 
                    if len(login_exist) != 0:
                        encrypted_response = encrypt("300", derived_key)
                        send(encrypted_response, conn)
                        #send("300", conn)
                    else:
                        query_users = Users.select().limit(1).order_by(Users.id_user.desc())
                        last_id_user = query_users.dicts().execute()
                        num_id = 0
                        if len(last_id_user) == 0:
                            new_user = Users.create(id_user=1, login=msg[1], password=hash.sha512(f'{msg[2] + salt_new_user}'.encode('utf8')).hexdigest(), e_mail=msg[3], salt=salt_new_user)
                            new_user.save()
                            num_id = 1
                        else:
                            new_user = Users.create(id_user=int(last_id_user[0]['id_user']) + 1, login=msg[1], password=hash.sha512(f'{msg[2] + salt_new_user}'.encode('utf8')).hexdigest(), e_mail=msg[3], salt=salt_new_user)
                            new_user.save()
                            num_id = int(last_id_user[0]['id_user']) + 1
                    	
                        query_sys_info = SystemInfo.select().limit(1).order_by(SystemInfo.id_system.desc())
                        last_id_sys_info = query_sys_info.dicts().execute()
                        ip_api = "http://ip-api.com/json/212.21.0.44"
                        response_ip_api = json.loads(requests.get(ip_api).text)
                    	
                        if len(last_id_sys_info) == 0:
                            new_user_sys_info = SystemInfo.create(id_system=1, user_id=num_id, ip_address=addr[0], mac_address=data_reg[0], pc_name=data_reg[1], os_name=data_reg[2], arch=data_reg[3], country=response_ip_api['country'], city=response_ip_api['city'])
                            new_user_sys_info.save()
                        else:
                            new_user_sys_info = SystemInfo.create(id_system=int(last_id_sys_info[0]['id_system']) + 1, user_id=num_id, ip_address=addr[0], mac_address=data_reg[0], pc_name=data_reg[1], os_name=data_reg[2], arch=data_reg[3], country=response_ip_api['country'], city=response_ip_api['city'])
                            new_user_sys_info.save()
                        query_temp_pass = TempPassword.select().limit(1).order_by(TempPassword.id_temp_pass.desc())
                        last_id_temp_pass = query_temp_pass.dicts().execute()	  		
                    	
                        if len(last_id_temp_pass) == 0:
                            new_temp_pass = TempPassword.create(id_temp_pass=1, user_id=num_id, count_attempts_pass=0)
                            new_temp_pass.save()
                        else:
                            new_temp_pass = TempPassword.create(id_temp_pass=int(last_id_temp_pass[0]['id_temp_pass']) + 1, user_id=num_id, count_attempts_pass=0)
                            new_temp_pass.save()
                        query_temp_otp = TempOtp.select().limit(1).order_by(TempOtp.id_temp_otp.desc())
                        last_id_temp_otp = query_temp_otp.dicts().execute()
                    	
                        if len(last_id_temp_otp) == 0:
                            new_temp_otp = TempOtp.create(id_temp_otp=1, user_id=num_id, count_attempts_otp=0)
                            new_temp_otp.save()
                        else:
                            new_temp_pass = TempOtp.create(id_temp_otp=int(last_id_temp_otp[0]['id_temp_otp']) + 1, user_id=num_id, count_attempts_otp=0)
                            new_temp_pass.save()
                        encrypted_response = encrypt("100", derived_key)
                        send(encrypted_response, conn)
                    	#send("100", conn)
                    	
                elif msg[0] == "reg_bio":
                    query_id_for_bio = Users.select().where(Users.login == msg[2])
                    id_for_bio = query_id_for_bio.dicts().execute()
                	
                    query_face_info = FaceInfo.select().limit(1).order_by(FaceInfo.id_face.desc())
                    last_id_face_info = query_face_info.dicts().execute()
                    face_vector = np.array(list(msg[1].replace("[", "").replace(", ", "").replace("]", "").replace(" ", "").replace("\n", "")), dtype=int)
                    if len(last_id_face_info) == 0:
                        new_face_info = FaceInfo.create(id_face=1, user_id=id_for_bio[0]['id_user'], vector=face_vector.tolist())
                        new_face_info.save()
                    else:
                        new_face_info = FaceInfo.create(id_face=int(last_id_face_info[0]['id_face']) + 1, user_id=id_for_bio[0]['id_user'], vector=face_vector.tolist())
                        new_face_info.save()
                    		
                elif msg[0] == "ch_pass":
                    salt_new_user = generate_salt()
                    query_update_password = Users.update(password=hash.sha512(f'{msg[1] + salt_new_user}'.encode('utf8')).hexdigest(), salt=salt_new_user).where(Users.login == user_login_pass)
                    query_update_password.execute()   
                    encrypted_response = encrypt("100", derived_key)
                    send(encrypted_response, conn)
                    #send("100", conn)
                    
                elif msg[0] == "ch_mail":
                    user.change_mail(msg[1])
                    encrypted_response = encrypt("100", derived_key)
                    send(encrypted_response, conn)
                    #send("100", conn)
                    
                elif msg[0] == "send_login":
                    query_login = Users.select().where(Users.login == msg[1])
                    user_login = query_login.dicts().execute()
                    if len(user_login) == 0:
                        encrypted_response = encrypt("400", derived_key)
                        send(encrypted_response, conn)
                        #send("400", conn)
                    else:
                        user_login_pass = user_login[0]['login']
                        encrypted_response = encrypt("100", derived_key)
                        send(encrypted_response, conn)
                        #send("100", conn)

        #except:
        	#pass

    conn.close()

def start():    
    server.listen()
    print(f'Server starts: {ip_server}')
    while True:
        conn, addr = server.accept()
        
        parameters_bytes = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
        send(parameters_bytes.decode('utf8'), conn)
        server_public_key_bytes = server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        send(server_public_key_bytes.decode('utf8'), conn)
        client_public_key_bytes = recv(conn).encode('utf8')
        client_public_key = load_pem_public_key(client_public_key_bytes)
        shared_key = server_private_key.exchange(client_public_key)
        derived_key = HKDF(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=None,
	    info=b'handshake data'
	).derive(shared_key)
        q = queue.Queue()
        thread = threading.Thread(target=handle_client, args=(conn, q, addr, derived_key))
        thread.start()
        print(f"Count active connections: {threading.active_count() - 1}")
    connect.close()

start()
