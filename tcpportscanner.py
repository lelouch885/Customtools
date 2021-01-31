# A simple tcp port scanner  made on the  concept of FULL TCP Connection i.e it uses a three way handshake to determine the availability of a port or service 



import optparse
import socket 
from socket import * 
from threading import * 

screenlock = Semaphore(value = 1)


def connectionScan(targethost,targetport):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(targethost,targetport)
		s.send("Hello form this side\r\n")
		results=s.recv(1000)
		screenlock.acquire()
		print('[+] {}/TCP Open '.format(targetport))
		print('[+]'+str(results))
		
	except:
		screenlock.acquire()
		print('[-] {}/TCP Closed '.format(targetport))
		
	finally:
		screenlock.release()
		#s.close()

def portScan(targethost,targetports):
	try:
		targetIP =gethostbyname(targethost)
	except:
		print('[-] Cannot reslove ip address {}: Unknown Host'.format(targethost))
		
		return
	try:
		targetName = getbyhostaddr(targetIP)
		print('\n[+] Scan results for : {}'.format(targetName))
		

	except:
		print('\n[+] Scan results for : {}'.format(targetIP))
		
#	setdefaulttimeout(1)

	for targetport in targetports :
		t = Thread(target=connectionScan,args=(targethost,int(targetport)))
		t.start()

def main():
	Usage = 'Usage%prog '+ \
		'-H  <Target Hostname > -P <Target Ports>'
	parser =optparse.OptionParser(usage = Usage)

	parser.add_option('-H',dest='targethost',type='string',\
		help='Specify target hostname')
	parser.add_option('-P','-p',dest='targetport',type='string',\
		default='80',help='Specify target ports separated by comma' )
	
	(options,args) = parser.parse_args()

	targethost=options.targethost

	targetports=str(options.targetport).split(',')

	

	if(targethost == None) or (targetports == None):
		print('[-]'+parser.usage)
		exit(0)
	portScan(targethost,targetports)
	
		



main()
