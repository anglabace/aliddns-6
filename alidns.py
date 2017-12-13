#!/bin/env python
# -*- coding: UTF-8 -*-
from __future__ import print_function
from __future__ import unicode_literals
import sys
if sys.version_info > (3,0): 
    from urllib import parse as urlparse
    from http import client as httpclient
else: 
    import urllib as urlparse
    import httplib as httpclient
import os
import logging
import json
import getopt
import subprocess
# import urllib
import hmac
import base64
import uuid
import datetime
import hashlib
import re
from hashlib import sha1
from collections import namedtuple
from pprint import pprint
# from timeparse import parse_time
import myip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def check_error(response):
    if 'Message' in response:
        eprint("Error: %s, %s" % (response['Code'] if 'Code' in response else '', response['Message']))
        return False
    else:
        return True

class Alidns():

    def __init__(self, accessKeyId, accessSecret, method='POST', format='JSON'):
        self.__params = {
            'Format': 'JSON',
            'AccessKeyId': accessKeyId,
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureVersion': '1.0',
            'Version': '2015-01-09',
        }
        self.__method = method
        self.__secret = accessSecret
        self.__conn = httpclient.HTTPSConnection('alidns.aliyuncs.com', 443)

    def __gensign(self, params):
        params_str = ''
        for key in sorted(params.keys()):
            params_str = params_str + key + '=' + params[key] + '&'
        params_str = params_str.rstrip('&')
        msg = self.__method + '&' + \
            urlparse.quote_plus(
                '/') + '&' + urlparse.quote_plus(params_str, safe=':-_.~')
        msg = msg.replace(':', '%253A')
        key = self.__secret + '&'
        res = hmac.new(key.encode(), msg.encode(), sha1).digest()
        return base64.b64encode(res).decode('utf-8')

    def request(self, custParams):
        params = dict(self.__params, **custParams)
        params['SignatureNonce'] = str(uuid.uuid1())
        if sys.version_info > (3, 0):
            params['Timestamp'] = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        else:
            params['Timestamp'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        params['Signature'] = self.__gensign(params=params)
        logger.debug('request_params: %s', str(params))
        self.__conn.request('POST', '', urlparse.urlencode(params), {
                            "Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"})
        return self.__conn.getresponse().read().decode('utf-8')

    def describeSubDomainRecords(self, subDomain, pageNumber=1, pageSize=20, type=None):
        params = {
            'Action': 'DescribeSubDomainRecords',
            'SubDomain': subDomain,
            'PageNumber': str(pageNumber),
            'PageSize': str(pageSize)
        }
        if(type):
            params['Type'] = type
        rsp = self.request(params)
        return json.loads(rsp)

    def describeDomainRecordInfo(self, recordId):
        params = {
            'Action': 'DescribeDomainRecordInfo',
            'RecordId': recordId
        }
        rsp = self.request(params)
        return json.loads(rsp)

    def updateDomainRecord(self, recordId, host, value, recordType='A'):
        params = {
            'Action': 'UpdateDomainRecord',
            'RecordId': recordId,
            'RR': host,
            'Type': recordType,
            'Value': value
        }
        rsp = self.request(params)
        return json.loads(rsp)


listDomain = False
updateDomain = False
ipsvr = None
ca = 'cacert.pem'
cert = 'clientcert.pem'
key = 'clientkey.pem'
port = 1234
accessFile = 'access.json'
access = {}
access_id = access_secret = None
record_id = None
record_rr = None
record_value = None
process = None

opts, args = getopt.getopt(sys.argv[1:], 'r:h:t:v:s:p:LU', [
                           'debug', 'accessid=', 'accesssecret=', 'delay=','ipsvr='])
domain = None
if len(args) > 0:
    domain = args[0]

record_type = 'A'

for opt, value in opts:
    if opt == '-L':
        listDomain = True
    if opt == '-U':
        updateDomain = True
    if opt == '-r':
        record_id = value
    if opt == '-h':
        record_rr = value
    if opt == '-t':
        record_type = value
    if opt == '-v':
        record_value = value
    if opt == '-s':
        accessFile = value
    if opt == '-p':
        process = value
    if opt == '--debug':
        logger.setLevel(logging.DEBUG)
    if opt == '--accessid':
        access_id = value
    if opt == '--accesssecret':
        access_secret = value
    if opt == '--ipsvr':
        ipsvr = value

if os.path.isfile(accessFile):
    with open(accessFile) as f:
        access = json.load(f)
if access_id:
    access['accessid'] = access_id
if access_secret:
    access['accesssecret'] = access_secret
if ('accessid' not in access) or ('accesssecret' not in access):
    print('Missing accessid or accesssecret')
    exit(1)
client = Alidns(access['accessid'], access['accesssecret'])

if listDomain:
    def printRecords(records):
        for (index, record) in enumerate(records):
            line = str(index) + ':'
            for key, value in record.items():
                line = line + key + '=' + str(value) + ':'
            line = line.rstrip(':')
            print(line)
    if domain:
        result = client.describeSubDomainRecords(domain)
        if not check_error(result):
            exit(1)
        printRecords(result['DomainRecords']['Record'])
    elif record_id:
        result = client.describeDomainRecordInfo(record_id)
        printRecords([result])
    else:
        eprint("Missing option")
        exit(1)
elif updateDomain:
    value = None
    if record_value:
        value = record_value
    elif process:
        p = subprocess.Popen(process, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outs, errs = p.communicate()
        if p.poll() == 0:
            value = outs.decode('utf-8').strip()
        else:
            eprint("Process %s failed: %s" % (process, errs))
            exit(1)
    elif ipsvr:
        print('Get ip from ' + ipsvr + '.')
        try:
            value = myip.getip(ipsvr,port,cert,key,ca)
        except Exception as e:
            eprint("Get ip failed: " + repr(e))
            exit(1)
        print('Get ip success, ip=' + value)
    params = {
        'value': value,
        'recordType': record_type
    }
    record_info = None
    if record_id:
        record_info = client.describeDomainRecordInfo(record_id)
        params['recordId'] = record_info['RecordId']
    elif domain:
        result = client.describeSubDomainRecords(domain)
        if not check_error(result):
            exit(1)
        for record in result['DomainRecords']['Record']:
            if record['Type'] == record_type:
                record_info = record
                break
        if not record_info:
            eprint('Update domain faild: Record not found')
            exit(1)
        params['recordId'] = record_info['RecordId']
    else:
        eprint('Error: Update domain need RecordId(-r) or sub domain name')
        exit(1)
    if record_info['Value'] == value:
        print('Current ip is newest.')
        exit(0)
    if not domain and record_info:
        domain = record_info['RR'] + '.' + record_info['DomainName']
    if record_rr:
        params['host'] = record_rr
    else:
        params['host'] = record_info['RR']
    print('Update domain %s with "%s" type "%s"' % (domain, value, record_type))
    ret = client.updateDomainRecord(**params)
    logger.debug("updateDomainRecord: " + str(ret))
    if check_error(ret):
        print('Update success.')
    else:
        exit(1)

