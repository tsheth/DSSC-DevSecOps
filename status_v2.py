#!/usr/bin/python
import sys
import getopt
import os
import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import json

smart_check_url = ''
smart_check_userid = ''
smart_check_password = ''
scan_id = ''
output = 'status'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def init(argv):
    try:
        opts, args = getopt.getopt(argv, "h:v",
                                   ["smart_check_url=", "smart_check_userid=", "smart_check_password=", "scan_id=",
                                    "output="])

    except getopt.GetoptError as error:
        print('Error Not enough Arguments')
        print(str(error))
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('scans.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("--smart_check_url"):
            global smart_check_url
            smart_check_url = arg

        elif opt in ("--smart_check_userid"):
            global smart_check_userid
            smart_check_userid = arg

        elif opt in ("--smart_check_password"):
            global smart_check_password
            smart_check_password = arg

        elif opt in ("--scan_id"):
            global scan_id
            scan_id = arg

        elif opt in ("--output"):
            global output
            output = arg


def get_token(userid, password):
    # print("----- Generating Token ----- "+userid)
    payload = {'user': {'userID': userid, 'password': password}}
    r = requests.post('https://' + smart_check_url + '/api/sessions', json=payload, verify=False)
    z = json.loads(r.text)
    return z


def get_scan(token, id):
    # print("----- Get Scan Data for "+id+" -----")
    headers = {
        'authorization': "Bearer " + token,
        'content-type': "application/json",
    }
    r = requests.get('https://' + smart_check_url + '/api/scans/' + id, headers=headers, verify=False)
    x = json.loads(r.text)

    if output == "status":
        print(x['status'])


    if output == "malware" and "malware" in x['findings']:
        if (x['findings']['malware'] > 0):
            print('malware_found')
            # sys.exit(os.EX_SOFTWARE)
        else:
            print('no-malware')


    if output == "contents" and "contents" in x['findings']:
        try:
            if (x['findings']['contents']['total']['high'] > 0):
                print(str(x['findings']['contents']['total']['high']) + ' Secret stored found in image!')
                # print('Critical Vulnerabilities Found')
                # sys.exit(os.EX_SOFTWARE)
            else:
                print('No Secrets found in image')
        except Exception as e:
            pass


    if output == "vulnerability" and "high" in x['findings']['vulnerabilities']['total']:
            try:
                if (x['findings']['vulnerabilities']['total']['high'] > 0):
                    print(str(x['findings']['vulnerabilities']['total']['high']) + ' High Vulnerabilities Found!')
                    # print('Critical Vulnerabilities Found')
                    # sys.exit(os.EX_SOFTWARE)
                else:
                    print('No High Vulnerabilities')
            except Exception as e:
                pass

            try:
                if (x['findings']['vulnerabilities']['total']['critical'] > 0):
                    print(
                        str(x['findings']['vulnerabilities']['total']['critical']) + ' Critical Vulnerabilities Found!')
                # print('Critical Vulnerabilities Found')
                # sys.exit(os.EX_SOFTWARE)
                else:
                    print('No Critical Vulnerabilities')
            except Exception as e:
                pass




init(sys.argv[1:])
token = get_token(smart_check_userid, smart_check_password)
# print(token)
get_scan(token['token'], scan_id)
