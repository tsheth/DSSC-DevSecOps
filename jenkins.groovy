pipeline {
   agent any
   environment {
          SMART_CHECK_SERVER=""
          AWS_REGION=""
          SCAN_REGISTRY=""
          SCAN_REPOSITORY=""
          SMART_CHECK_CREDS=credentials('')
          AWS=credentials('')
          SCAN_ID="xxx"
    }
    stages
    {
        stage('Checkout') { // for display purposes
           steps{
                sh 'printenv'
                checkout([$class: 'GitSCM', branches: [[name: '*/master']], doGenerateSubmoduleConfigurations: false, extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'smart-check']], submoduleCfg: [], userRemoteConfigs: [[url: 'https://github.com/tsheth/docker-vulnerable-dvwa.git']]])
            }
        }
        stage('Build') {
            steps{
                sh("docker build -t $SCAN_REGISTRY/$JOB_BASE_NAME:$BUILD_ID $WORKSPACE/smart-check")
            }
        }
        stage('Send to Repository') {
              steps{
                  script{
                      sh("eval \$(aws ecr get-login --region us-east-2 --no-include-email | sed 's|https://||')")
                      sh("docker push $SCAN_REGISTRY/$JOB_BASE_NAME:$BUILD_ID")
                  }

            }
        }
        stage('Scan for Malware and Vulnerabilities')
        {
            steps{
                script {
                    def SCAN_ID = sh (
                        script: "python3 smart-check/scans_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}'  --scan_registry='${SCAN_REGISTRY}'  --scan_repository='${JOB_BASE_NAME}'  --scan_tag='${BUILD_ID}'  --aws_region='${AWS_REGION}'  --aws_id='${AWS_USR}'  --aws_secret='${AWS_PSW}'",
                        returnStdout: true
                    ).trim()

                    echo "SCAN_ID print: ${SCAN_ID}"

                    for (int i = 0; i < 120; i++) {
                            def index = i
                            def SCAN_RESULT = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='status'",
                                returnStdout: true
                            ).trim()
                            echo "${SCAN_RESULT}"

                            if("${SCAN_RESULT}" == "completed-with-findings")
                            {

                               break;
                            }
                            sh 'sleep 60'

                    }
                    def SCAN_VULNERABILITY = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='vulnerability'",
                                returnStdout: true
                             )


                    def SCAN_MALWARE = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='malware'",
                                returnStdout: true
                             )

                    def SCAN_CONTENT = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='contents'",
                                returnStdout: true
                             )
                    echo "Secret Found: ${SCAN_CONTENT}"
                    echo "Malware Result: ${SCAN_MALWARE}"
                    echo "Vulnerability Result: ${SCAN_VULNERABILITY}"

                    if("${SCAN_MALWARE}" != "")
                    {
                        slackSend color: "danger", message: "Job: ${env.JOB_NAME} with buildnumber ${env.BUILD_NUMBER} was not deployed because there was malicious file detected in image. For more details visit (<${env.BUILD_URL}|Open>)"
                        echo "[FAILURE] Malware Found in image"
                    }

                    if("${SCAN_VULNERABILITY}" != "")
                    {
                        slackSend color: "warning", message: "Job: ${env.JOB_NAME} with buildnumber ${env.BUILD_NUMBER} was not deployed because vulnerability detected in container image. For more details visit (<${env.BUILD_URL}|Open>)"
                        echo "[FAILURE] Vulnerability Found in image"
                    }

                    if("${SCAN_CONTENT}" != "")
                    {
                        slackSend slackSend color: "danger", message: "Job: ${env.JOB_NAME} with buildnumber ${env.BUILD_NUMBER} was not deployed because Secret or credentials detected in container image.Its recommended to remove any credentials and secrets from container image. For more details visit (<${env.BUILD_URL}|Open>)"
                        echo "[FAILURE] Secrets Found in image. Its recommended to remove any credentials and secrets from container image"
                    }
                    if("${SCAN_MALWARE}" != "" || "${SCAN_VULNERABILITY}" != "" || "${SCAN_CONTENT}" != "")
                    {
                        currentBuild.result = 'FAILURE'
                        sh "exit ${result}"
                    }
                }
            }
        }
        stage('Certify Release')
        {
            steps{
                sh ("docker tag $SCAN_REGISTRY/$JOB_BASE_NAME:$BUILD_ID $SCAN_REGISTRY/$JOB_BASE_NAME:latest")
            }
        }
        stage('Deploy to Production')
        {
            steps{
                sh ("docker push $SCAN_REGISTRY/$JOB_BASE_NAME:latest")
               script {
					def remote = [:]
					withCredentials([sshUserPrivateKey(credentialsId: 'docker-host', keyFileVariable: 'identity', passphraseVariable: '', usernameVariable: 'userName')]) {
						 remote.user = userName
						 remote.identityFile = identity
						 remote.name = "web-server"
						 remote.host = "<HOSTIP>"
						 remote.allowAnyHosts = true
						 sshCommand remote: remote, command: 'sudo docker login -u AWS -p "<key>" 650143975734.dkr.ecr.us-east-2.amazonaws.com'                 
						 sshCommand remote: remote, command: 'sudo docker stop struts_app'
						 sshCommand remote: remote, command: 'sudo docker rm struts_app'
						 sshCommand remote: remote, command: 'sudo docker run -d -p 8080:80 --name struts_app 650143975734.dkr.ecr.us-east-2.amazonaws.com/stage3-webapp:latest'
					}
				}
            }

        }
    }
}
