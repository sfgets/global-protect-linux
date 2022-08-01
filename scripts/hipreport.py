from argparse import ArgumentParser
from datetime import datetime
import xml.etree.ElementTree as ET
import os

REPORT = '~/vpn/hip-report.xml'

def parse_cookie(cookie: str) -> dict:

  alltags = cookie.split(sep='&')
  tags = dict(a.split(sep='=') for a in alltags)
  for k, v in tags.items():
    if "empty" in v:
      tags.update({k:'empty_domain'})
  return tags

def mapdict(keys: list, cookie: dict) -> dict:
  tags = {}
  mapr = {'user': 'user-name', 'domain':'domain', 'computer':'host-name'}
  for i in keys:
    for k,v in mapr.items():
      if i == v:
        tags.update({i:cookie.get(k)})
      elif "generate" in i:
        tags.update({i:datetime.now().strftime('%m/%d/%Y %H:%M:%S')})
      elif i == 'ip-address':
        tags.update({i:args.client_ip})
      elif i == 'md5-sum':
        tags.update({i:args.md5})
  return tags


if __name__ == "__main__":
  parser = ArgumentParser()
  parser.add_argument("--cookie", required=False, default=os.environ.get("COOKIE"))
  parser.add_argument("--client-ip", required=False, default=os.environ.get("IPADDRESS"))
  parser.add_argument("--md5", required=False, default=os.environ.get("MD5SUM"))
  args, extra = parser.parse_known_args()

  keys = ["md5-sum", "user-name", "domain", "host-name", "ip-address", "generate-time"]

  try: 
    xml = ET.parse(os.path.expanduser(REPORT))
    mapped_tags = mapdict(keys=keys, cookie=parse_cookie(cookie=args.cookie)) 
    root = xml.getroot()
    childs = [ c.tag for c in root ]

#Initialize and add required subelements to the root tree
    for k in keys:
      if k not in childs:    
        sub = ET.SubElement(root, k)

#Update newly creates subelements with data privided
    for child in root:
      if child.tag in keys:
        child.text = mapped_tags.get(child.tag)
  
# remove and readd categories to keep newly added elements on the top of the tree
    for child in root:
      if child.tag == 'categories':
        cat = child
        root.remove(child)
        root.append(cat)

    ET.dump(root)
    
  except Exception as e:
    raise