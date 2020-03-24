#!/bin/python3
import sys
import json
import urllib.parse as upar
from urllib.parse import parse_qs
BASE= open("/etc/qlx/BASE","r").readline().strip()
site= sys.argv[1]
folder= BASE+"/"+site+"/"

print("[+]waybacking "+site)
uniq= {}
for url in sys.stdin:
    obj= upar.urlparse(url.strip())
    if obj.path == '':
        obj= obj._replace(path='/')
    noparam= obj.scheme+"://"+obj.netloc+obj.path
    query= parse_qs(obj.query)
    if noparam not in uniq:
        uniq[noparam]= query
    else:
        for param in query:
            if param not in uniq[noparam]:
                uniq[noparam][param]= query[param]

urlfile= open(folder+".urls","w+")
for key in uniq.keys():
    if uniq[key]:
        url= key+"?"
        for param in uniq[key].keys():
            url= url + param + "=" + uniq[key][param][0] + '&'
        url= url.rstrip('&')
        urlfile.write("%s\n" % url)
urlfile.close()

open(folder+".raw.json","w+").write(json.dumps(uniq))
print("[+]"+site+" finished")