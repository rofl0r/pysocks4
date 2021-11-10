# socks4 server library routines for python.
# Copyright (C) 2021 rofl0r

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

# you can find the full license text at
# https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html


import socket, select, sys

PY3 = sys.version_info[0] == 3
if PY3:
	def _ord(x):
		return x
	def _b(a, b):
		return bytes(a, b)
	def _byte(s, pos):
		return s[pos:pos+1]
else:
	def _ord(x):
		return ord(x)
	def _b(a, b):
		return bytes(a)
	def _byte(s, pos):
		return s[pos]

def _format_addr(addr):
	ip, port = addr
	ip = _b(ip, 'utf-8')
	return b"%s:%d"%(ip, port)

def _isnumericipv4(ip):
	try:
		a,b,c,d = ip.split('.')
		if int(a) < 256 and int(b) < 256 and int(c) < 256 and int(d) < 256:
			return True
		return False
	except:
		return False

def _resolve(host, port, want_v4=True):
	if _isnumericipv4(host):
		return socket.AF_INET, (host, port)
	for res in socket.getaddrinfo(host, port, \
			socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
		af, socktype, proto, canonname, sa = res
		if want_v4 and af != socket.AF_INET: continue
		if af != socket.AF_INET and af != socket.AF_INET6: continue
		else: return af, sa
	return None, None


class Socks4Client():
	def __init__(self, addr, conn):
		self.addr = addr
		self.conn = conn
		self.active = True
		self.debugreq = False

	def do(self):
		try:
			pkt = self.conn.recv(9)
		except:
			self.disconnect()
			return

		if len(pkt) != 9:
			self.disconnect()
			return

		ver  = _ord(pkt[0])
		meth = _ord(pkt[1])

		if ver != 4 or meth != 1:
			return self.fail(b"\x5b")

		port = _ord(pkt[2]) * 256 + _ord(pkt[3])
		ip   = b"%d.%d.%d.%d"%( _ord(pkt[4]), _ord(pkt[5]), _ord(pkt[6]), _ord(pkt[7]) )
		hostname = ip

		user = b''
		ch = _byte(pkt, 8)
		while ch != b'\0':
			try:
				ch = self.conn.recv(1)
				user += ch
			except:
				self.disconnect()
				return

		support_socks4a = True
		if support_socks4a and _ord(pkt[4]) == 0 and _ord(pkt[5]) == 0 and _ord(pkt[6]) == 0:
			hostname = b''
			ch = b'x'
			while ch != b'\0':
				try:
					ch = self.conn.recv(1)
					hostname += ch
				except:
					return self.disconnect()

		try:
			af, sa = _resolve(hostname, port)
		except socket.gaierror: return self.fail(b"\x5b")
		try:
			x = af+1
		except TypeError:
			try:
				af, sa = _resolve(hostname, port, False)
				x = af+1
			except:	return self.fail(b"\x5b")
		sock = socket.socket(af, socket.SOCK_STREAM)
		sock.settimeout(15)
		try: sock.connect((sa[0], sa[1]))
		except: return self.fail(b"\x5b")
		try: self.send(b"\0\x5a\0\0\0\0\0\0")
		except: return self.disconnect()
		fds = self.conn
		fdc = sock
		while True:
			a,b,c = select.select([fds, fdc], [], [])
			try: buf = a[0].recv(1024)
			except: buf = ''
			if len(buf) == 0: break
			try:
				if a[0] == fds: fdc.send(buf)
				else: fds.send(buf)
			except: break
		return self.disconnect()

	def _send_i(self, data):
		self.conn.send(data)
		if self.debugreq and len(data): print(b">>>\n", data)

	def send(self, data):
		try:
			self._send_i(data)
		except:
			self.disconnect()

	def fail(self, code):
		self.send(b"\0%c\0\0\0\0\0\0"%code)
		self.disconnect()

	def disconnect(self):
		if self.active: self.conn.close()
		self.conn = None
		self.active = False


class Socks4Srv():
	def __init__(self, listenip, port):
		self.port = port
		self.listenip = listenip
		self.s = None

	def setup(self):
		af, sa = _resolve(self.listenip, self.port)
		s = socket.socket(af, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((sa[0], sa[1]))
		s.listen(128)
		self.s = s

	def wait_client(self):
		conn, addr = self.s.accept()
		c = Socks4Client(addr, conn)
		return c

def socks4_client_thread(c, evt_done):
	c.do()
	c.disconnect()
	evt_done.set()

if __name__ == "__main__":
	import threading, sys
	ss = Socks4Srv('0.0.0.0', 1080)
	ss.setup()
	client_threads = []
	while True:
		c = ss.wait_client()
		sys.stdout.write("[%d] %s\n"%(c.conn.fileno(), _format_addr(c.addr)))
		evt_done = threading.Event()
		cthread = threading.Thread(target=socks4_client_thread, args=(c,evt_done))
		cthread.daemon = True
		cthread.start()

		ctrm = []
		for ct, ct_done in client_threads:
			if ct_done.is_set():
				ctrm.append((ct,ct_done))
				ct.join()

		if len(ctrm):
			client_threads = [ x for x in client_threads if not x in ctrm ]

		client_threads.append((cthread, evt_done))
