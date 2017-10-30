import sys
import socket
import signal
import parser

def terminateServer(signal, frame):
	print('\nTerminating server... \n')
	print('Goodbye!')
	sys.exit(0)

def runServer(port):
	# Create a TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = ('localhost', port)

	print('Server starting on \'%s\' port %s \n' % server_address)

	# Bind the socket
	try:
		sock.bind(server_address)
	
	except socket.error as exc:
		print('socket.error: %s' %exc)
		sys.exit(63)

	# Listen for incoming connections...
	sock.listen(1)

	while True:
		signal.signal(signal.SIGINT, terminateServer)

		# Wait for a connection
		print('Listening... \n')
		connection, client_address = sock.accept()

		try:
			print('-------------------------------------')
			print('Connection from ', client_address)

			data = connection.recv(8000000)
			data = (str(data.decode('ascii'))).rstrip()
			print(data)
			parser.messageHandler(data)
			print('-------------------------------------')

		finally:
			connection.close()
