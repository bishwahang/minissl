import sys
from socket import *
import threading
from keyutils import *
from binascii import hexlify,unhexlify
from datetime import datetime
import hashlib,os
#Declaring global variables
clientthreads=[]
server_force={}
queueLock = threading.Lock()
enc_mode="AES-CBC-128-HMAC-SHA1"
ca_path="certs/minissl-ca.pem" #root CA path
fmt = '%Y%m%d%H%M%S'
enc="00000000"
mac="11111111"
#Thread class implementation
class Client(threading.Thread):
	def __init__(self, addr, client):
		threading.Thread.__init__(self)
		self.addr = addr
		self.client = client
		self.nonce=""
		self.k1=""
		self.k2=""
		self.p=""
		print "Creation of new thread for:",self.addr
	def run(self):
		try:
			print "Connection from: ",self.addr
			self.client.send("Server: Welcome Abroad!")
			running=True
			client_nonce=""
			enc_mode=""
			clinet_init_mssg=""
			server_init_mssg=""
			client_kex_mssg=""
			while running:
				result=""
				msg=self.client.recv(4096)
				# print "message:",msg
				if not msg:
					#Socket might have been closed or something might have gone wrong
					#both cases, exit the loop
					running=False
					continue
				#Check for the level of message sent by client
				if "ClientInit" in msg:
					clinet_init_mssg=msg
					values=msg.split(",")
					client_nonce=values[1]
					enc_mode=values[2]
					print "Using "+enc_mode+" for the encryption and MAC."
					self.nonce=hexlify(generate_nonce())
					result="ServerInit,"+self.nonce+","+enc_mode+","+server_force["cert"]
					if server_force["mode"]:
						result=result+","+"CertReq"
					server_init_mssg=result
				elif "ClientKex" in msg:
					client_kex_mssg=msg
					values=msg.split(",")
					p_enc=values[1]
					iv=values[2]
					aes_key=values[3]
					mc=values[4]
					if(server_force["mode"]):
						if (len(values) != 7):
							print "Client did not provied certificate and signature as asked"
							print "Disconnecting the connection"
							running=False
							continue
						
						client_cert=values[5]
						if not check_cert(client_cert):
							print "Certifcate looks fishy, cancelling the handshake"
							running=False
							continue
						#Extracting signature and converting to tuple object
						client_sign=values[6]
						client_sign=(long(client_sign),)
						client_pubkey=read_pubkey_from_pem(client_cert)
						check_value=self.nonce+p_enc+iv
						#Check if the nocne value concatenatd with secret P is equal or not
						if not (client_pubkey.verify(check_value,client_sign)):
							print "Signining does not match"
							print "Disconnecting the handshake"
							running=False
							continue			
					#Decrypt the aes_key used using the server private key
					server_cipher=PKCS1_OAEP.new(server_force["pk"])
					key=server_cipher.decrypt(unhexlify(aes_key))
					#Decrypt encoded p to get the common secret p
					self.p=decrypt_with_rsa_hybrid(unhexlify(p_enc),unhexlify(iv),key)
					k1_str=client_nonce+self.nonce+enc
					k2_str=client_nonce+self.nonce+mac
					self.k1=create_hmac(self.p,k1_str)
					self.k2=create_hmac(self.p,k2_str)
					mc_str=clinet_init_mssg.replace(",","")+server_init_mssg.replace(",","")
					mc_to_check=hexlify(create_hmac(self.k2,mc_str))
					if not (mc==mc_to_check):
						print "Hash value of Mc doesnot match"
						print "Disconnecting handhsake"
						running=False
						continue
					#Create the final ms message to send to client
					concat_mssg=client_kex_mssg.replace(",","")
					ms=create_hmac(self.k2,concat_mssg)
					# iv=generate_random(16)
					# cipher_aes = AES.new(self.k1, AES.MODE_CFB, iv)
					# aes_enc_msg = cipher_aes.encrypt(msg)
					result="MS,"+hexlify(ms)

				elif "GET" in msg:
					#read the contents of data
					file_data=read_file(server_force["filename"])
					#create the digest of data
					digest=hashlib.sha1(file_data).hexdigest()
					#encrypt file
					iv=hexlify(generate_random(16))
					cipher_aes = AES.new(self.k1, AES.MODE_CFB, unhexlify(iv))
					enc_file=hexlify(cipher_aes.encrypt(file_data))
					#Concatenating all the data for Mac
					mac_string=iv+enc_file+digest
					#using Enc and then Mac approach
					hmac=hexlify(create_hmac(self.k2,mac_string))
					#sending encrypted file along with hmac of the concatenated datas
					result="File,"+iv+","+enc_file+","+digest+","+hmac
				elif (msg=="success"):
					print "File was downloaded successfully with sha1sum matching."
					break
				self.client.send(result)
				
		except Exception, e:
			print "Disconnected with error(s):",e
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno)
		else:
			print "Disconnected without any error(s): ",self.addr
		finally:
			self.client.close()
			clientthreads.remove(self)
			print "Thread closed."

"""
This will decrypt a message with an RSA public key.

Arguments:
msg -- encrypted message
iv -- iv used during encryption
key-- key used for encryption

Returns:
plaintext -- binary string
"""
def decrypt_with_rsa_hybrid(msg,iv,key ):
    cipher_aes=AES.new(key, AES.MODE_CFB,iv)
    return cipher_aes.decrypt(msg)

def check_cert(server_pem):
	#checks whether the certifacate was issued by rootCA in the database
	if not verify_certificate(read_file(ca_path),server_pem):
		print "root CA does not verifies the certifacate"
		return False
	#Get the valid date string from cert
	validity=read_notafter(server_pem)[0:-2]
	#Convert the date to date object
	untill=datetime.strptime(validity,fmt)
	now=datetime.strptime(datetime.now().strftime(fmt),fmt)
	if((untill-now).days <= 0):
		print "Not taking any risk, certifacate is expired."
		return False
	return True

def start_server(listen_port):

	#Creating a new socket with TCP stream
	s = socket(AF_INET,SOCK_STREAM)
	s.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
	#bind to localhost of the server machine
	s.bind(('', int(listen_port)))
	# max 10 connections to  be allowed in backlog
	s.listen(3)

	#Trivial flags for chekcing and debugging
	running=True
	said=False

	while running:
		if(len(clientthreads) >10):
			#Maximum 10 threads has been started, so wait for any one to complete
			#print the message and continue the loop
			if not said:
				print "Hold on Speedy...max 10 thread started already"
				print "Waiting for any single thread to finish..."
				said=True
			continue
		#change the said flag to flase for next iteration if max threads are created
		if said:
			print "...accepting requests from client again."
			said=False

		#Start accepting the requests
		try:
			client,addr = s.accept()
			newthread = Client(addr,client)
			newthread.start()
			clientthreads.append(newthread)
		except Exception, e:
			print "Exception caught: ",e
			running=False
		else:
			pass
		finally:
			pass
				
	# print "%d numbers of requests were handled by the server!",count
	# print "Auf Wiedersehen, und bis bald"
#Reads file form the path and returns string
#Reads file form the path and returns string
def read_file(path):
	reader= open(path, "rb")
	data=reader.read()
	reader.close()
	return data

def main():
	args=sys.argv[1:]
	if len(args)==5:
		listen_port=args[0]
		servercert=args[1]
		serverprivkey=args[2]
		auth=args[3].lower()
		file_name=args[4]
		print "Listening to: "+listen_port + " with Server Certificate: "+servercert +" and Server PrivKey: "+serverprivkey + ".\nMode: "+auth+" File to be transferred: "+file_name+"."
		#Set default mode to simple auth unless clien auth is specified
		ca_mode=False
		if(auth=="clientauth" or auth=="ca" ):
			ca_mode=True
		#Put all the needed items in one strong Force
		serv_pem=read_file(servercert)
		serv_pk=read_privkey_from_pem(read_file(serverprivkey))
		server_force["cert"]=serv_pem
		server_force["pk"]=serv_pk
		server_force["mode"]=ca_mode
		server_force["filename"]=file_name
		#May the force be with you
		start_server(listen_port)
	else:
		print "One or more arguemnts mismatch.Read the usage guidelines carefully..."
		print "Usage: server.py listen_port servercert serverprivkey {SimpleAuth, ClientAuth} payload.txt"
		print "shortcut: 'sa' or ca' can be used to switch between SimpleAuth or ClientAuth mode respectively.It is case insensitive"
		print "Certificates,Key,and File name should be given with exact path."
		
if __name__ == '__main__': main()