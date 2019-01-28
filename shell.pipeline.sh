#~~~~~~~~~~~~~~~~~
#Smart Check Scan:
#~~~~~~~~~~~~~~~~~

cd /opt/Smart-Check/

SCAN_ID=$(python3 scans_v2.py  --smart_check_url='<smartcheck URL:port>'  --smart_check_userid='administrator'  --smart_check_password='<password>'  --scan_registry='<Docker registry>'  --scan_repository='<Reopsitory/image>'  --scan_tag='<tag>' --aws_region='ap-southeast-1'  --aws_id='<Access_key>' --aws_secret='<secret_key>')

echo "SCAN_ID: ${SCAN_ID}"

for i in {1..120}
do
	echo "$i times"
	SCAN_RESULT=$(python3 status_v2.py  --smart_check_url='<smartcheck URL:port>'  --smart_check_userid='administrator'  --smart_check_password='<password>' --scan_id=$SCAN_ID --output='status')
	echo "Scan Result: ${SCAN_RESULT}"
	if [ $SCAN_RESULT == 'completed-with-findings' ]
	then
    	echo "Scan Result: ${SCAN_RESULT}"
    	break    
	fi
    sleep 60
	echo "Scan Result: ${SCAN_RESULT}"
done


SCAN_MALWARE=$(python3 status_v2.py  --smart_check_url='<smartcheck URL:port>'  --smart_check_userid='administrator'  --smart_check_password='<password>' --scan_id=$SCAN_ID --output='malware')

echo "Malware Result: ${SCAN_MALWARE}"

if [ $SCAN_MALWARE == 'malware_found' ]
    then
    echo "Malware Found"	
    break
    else
    echo "No Malware Found"
fi

SCAN_VULNERABILITY=$(python3 status_v2.py  --smart_check_url='<smartcheck URL:port>'  --smart_check_userid='administrator'  --smart_check_password='<password>' --scan_id=$SCAN_ID --output='vulnerability')

echo "Vulnerability Result: ${SCAN_VULNERABILITY}"

if [ $SCAN_VULNERABILITY != '' ]
    then
    echo "Critical Vulnerabilities Found in Docker image"  
    else
    echo $SCAN_VULNERABILITY    
    break
fi

SCAN_SECRET=$(python3 status_v2.py  --smart_check_url='<smartcheck URL:port>'  --smart_check_userid='administrator'  --smart_check_password='<password>' --scan_id=$SCAN_ID --output='contents')

echo "Secret Result: ${SCAN_SECRET}"

if [ $SCAN_SECRET != '' ]
    then
    echo "Secret Found in Docker image"  
    else
    echo $SCAN_SECRET   
    break
fi

echo "Deployment Pending for now...."
