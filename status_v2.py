#!/usr/bin/python
import sys, getopt, os
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning


smart_check_url=''
smart_check_userid=''
smart_check_password=''
scan_id=''
output='status'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def init(argv):

   try:
      opts, args = getopt.getopt(argv,"h:v",["smart_check_url=","smart_check_userid=","smart_check_password=","scan_id=","output="])

   except getopt.GetoptError as error:
      print 'Error Not enough Arguments'
      print str(error)
      sys.exit(2)

   for opt, arg in opts:
      if opt == '-h':
         print 'scans.py -i <inputfile> -o <outputfile>'
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

def get_token(userid,password):
    #print("----- Generating Token ----- "+userid)
    payload = {'user':{'userID': userid, 'password': password}}
    r = requests.post('https://'+smart_check_url+'/api/sessions', json=payload, verify=False)
    #print(r)
    z = json.loads(r.text)
    #print(z['token'])
    return z


def get_scan(token,id):
    #print("----- Get Scan Data for "+id+" -----")
    headers = {
        'authorization': "Bearer " + token,
        'content-type': "application/json",
    }
    r = requests.get('https://'+smart_check_url+'/api/scans/'+id, headers=headers, verify=False)
    x = json.loads(r.text)
	
    if output == "status":
        print(x['status'])
    else output == "malware" and "malware" in x['findings']:
        if(x['findings']['malware'] > 0):
            print('malware_found')
            sys.exit(os.EX_SOFTWARE)
        else:
            print('no-malware')
    try:
        if output == "vulnerabilities" and "vulnerabilities" in x['findings']:
            total_findings = x['findings']['vulnerabilities']['total']
            if(total_findings['critical'] > 0):
                print('critical_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            elif(total_findings['high'] > 0):
                print('high_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            elif(total_findings['medium'] > 0):
                print('medium_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            elif(total_findings['low'] > 0):
                print('low_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            elif(total_findings['negligible'] > 0):
                print('negligible_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            elif(total_findings['unknown'] > 0):
                print('unknown_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            elif(total_findings['defcon1'] > 0):
                print('defcon1_vulnerability_found')
                sys.exit(os.EX_SOFTWARE)
            else:
                print('no-malware no-vulnerabilities')
    except Exception as e:
            pass
            print('no-malware no-vulnerabilities')
			
    print(r.text)


init(sys.argv[1:])
#print(smart_check_userid)
token = get_token(smart_check_userid,smart_check_password)
#print (token['token'])
get_scan(token['token'],scan_id)
