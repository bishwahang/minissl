
import sys
from socket import *
from keyutils import *
from binascii import a2b_base64,b2a_base64,hexlify,unhexlify
from datetime import datetime
import hashlib,os

#Declaring global variables
filename="downloaded_payload.txt"
client_force={}
ca_path="certs/minissl-ca.pem" #root CA path
company_name="minissl-SERVER"
enc_mode="AES-CBC-128-HMAC-SHA1"
fmt = '%Y%m%d%H%M%S'
enc="00000000"
mac="11111111"


def connect_server(addr):
	s = socket(AF_INET,SOCK_STREAM) # Create a TCP socket
	s.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
	try:
		# Connect to the server and print the welcome message
		s.connect(addr)
		p=""
		print "Conneted to:",addr
		print s.recv(2048)
		#make the first ClientInit message and send it to server
		nc=hexlify(generate_nonce())
		client_init="ClientInit,"+nc+","+enc_mode
		s.send(client_init)
		
		#defining some variables for loop and certificate request
		running=True
		cert_req=False
		ClientKex=""
		k1=""
		k2=""
		success=False
		while running:
			#initialize result and wait for message receive
			result=""
			msg=s.recv(4096)

			#if msg is empty, server rejected the handshake
			if not msg:
				#Socket might have been closed or something might have gone wrong
				#both cases, exit the loop
				print "Server rejected the handshake..."
				running=False
				continue

			#check for the right flag in the message
			if "ServerInit" in msg:
				#Spliting the message and processing each value
				values=msg.split(",")
				ns=values[1]
				serv_pem=values[3]
				if(len(values) == 5):
					#certificate was requested by server
					cert_req=True
				if not check_cert(serv_pem):
					print "Certifcate looks fishy, cancelling the handshake"
					running=False
					continue
				#Certificate is good generate the pre master and keys
				serv_pub_key=read_pubkey_from_pem(serv_pem)
				p=generate_random(46)
				k1_str=nc+ns+enc
				k2_str=nc+ns+mac
				k1=create_hmac(p,k1_str)
				k2=create_hmac(p,k2_str)
				mc_str=client_init.replace(",","")+msg.replace(",","")
				mc=hexlify(create_hmac(k2,mc_str))
				esp=encrypt_with_rsa_hybrid(p,serv_pub_key)
				p_enc=hexlify(esp[0])
				iv=hexlify(esp[1])
				aes_key=hexlify(esp[2])
				ClientKex="ClientKex,"+p_enc+","+iv+","+aes_key+","+mc
				#Certificate is requeted so sign the secret p, iv, and the nonce of server
				#So as to make sure it was not replay attack and there was no forgery of data
				if cert_req:
					text=ns+p_enc+iv
					sign=str(client_force["pk"].sign(text,'')[0])
					ClientKex=ClientKex+","+client_force["cert"]+","+sign
				result=ClientKex
			elif "MS" in msg:
				values=msg.split(",")
				hmac=values[1]
				hmac_string=ClientKex.replace(",","")
				hmac_to_check=hexlify(create_hmac(k2,hmac_string))
				if not (hmac_to_check==hmac):
					print "Data was forged on transmission,final MS hamac does not match"
					print "Disconnecting handshkae"
					running=False
					continue
				result="GET "+filename
			elif "File" in msg:
				values=msg.split(",")
				iv=values[1]
				enc_file=values[2]
				digest=values[3]
				hmac=values[4]

				#Check the mac for any forgery on the transport of package
				mac_str=iv+enc_file+digest
				mac_to_check=hexlify(create_hmac(k2,mac_str))
				if not (mac_to_check==hmac):
					print "File contents forged, disconnectin..."
					running=False
					continue

				#Decrypt file since no forgery
				iv=unhexlify(iv)
				cipher_aes = AES.new(k1, AES.MODE_CFB, iv)
				file_data=cipher_aes.decrypt(unhexlify(enc_file))

				#computer Sha1 digest and compare
				sha1_to_check=hashlib.sha1(file_data).hexdigest()
				if not (sha1_to_check==digest):
					print "Digest doest not match, rejecting file and Disconnecting..."
					running=False
					continue
				f = open(filename, 'wb')
				f.write(file_data)
				f.close()
				#Set success flag true
				success=True
				#send succes acknowledgement to server
				result="success"
				#stop the loop
				running=False
			else:
				print "Thou shalt not pass"
			s.send(result)
		if success:
			print "minissl and miniget connection completed successfully!"
			print "File '%s' downloaded securely."%filename
	except Exception, e:
		print "Disconnected with error(s):",e
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
	else:
		print "Disconnected without any error(s): ",addr
	finally:
		print "Closing any open socket..."
		s.close()
	print "Goodbye!"
#Checks Certificate
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
	#Get Company name
	cn=read_subject(server_pem).CN
	#Check with default company name which is defined at global variale
	if not cn==company_name:
		print "Company name does not match"
		return False
	return True

#Reads file form the path and returns string
def read_file(path):
	reader= open(path, "rb")
	data=reader.read()
	reader.close()
	return data

def main():
	args=sys.argv[1:]
	if len(args)==4:
		dst_ip=args[0]
		dst_port=args[1]
		clientcert=args[2]
		clientprivkey=args[3]
		print "Destination IP: "+dst_ip + " Destination Port: "+dst_port +".\nClinet Cert: "+clientcert + " Client Priv Key: "+clientprivkey
		client_pem=read_file(clientcert)
		client_pk=read_privkey_from_pem(read_file(clientprivkey))
		client_force["cert"]=client_pem
		client_force["pk"]=client_pk
		client_force["dst_ip"]=dst_ip
		client_force["dst_port"]=dst_port
		addr=(dst_ip,int(dst_port))
		connect_server(addr)
	else:
		print "One or more arguemnts mismatch.Read the usage guidelines carefully..."
		print "Usage: client.py dst_ip dst_port clientcert clientprivkey"
		print "Certificates and Key name should be given with exact path."
		

if __name__ == '__main__': main()