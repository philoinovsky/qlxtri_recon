#!/bin/python3
import sys
import json
import urllib.parse as upar
from urllib.parse import parse_qs
BASE= open("/etc/qlx/BASE","r").readline().strip()
site= sys.argv[1]
folder= BASE+"/"+site+"/"
paramlist= list(map(str.strip,open("/usr/share/wordlists/urlpara.txt").readlines()))
payloads= list(map(str.strip,open("/usr/share/wordlists/ssrfpayload.txt").readlines()))

uniq= json.loads(open(folder+".raw.json","r").readline().rstrip())
print("[+]searching "+site)
urlfile= open(folder+".ssrfurl","w+")
for key in uniq:
    urls= []
    tag=0
    if uniq[key]:
        urls= [key + "?" for param in paramlist]
        for param in uniq[key]:
            if param in paramlist:
                urls= [url + param + "=" + payload + '&' for url,payload in zip(urls,payloads)]
                tag=1
            else:
                urls= [url + param + "=" + uniq[key][param][0] + '&' for url in urls]
        if tag:
            for url in urls:
                urlfile.write("%s\n" % url.rstrip('&'))
urlfile.close()