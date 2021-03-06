pipeline {
   agent any
   environment {
          SMART_CHECK_SERVER=""
          SCAN_REGISTRY=""
          SCAN_REPOSITORY=""
          SMART_CHECK_CREDS=credentials('smart_check_jaws_world')
          ACR_CRED=credentials('azure-acr')
          SCAN_ID="xxx"
    }
    stages
    {
        stage('Checkout') { // for display purposes
           steps{
                sh 'printenv'
                checkout([$class: 'GitSCM', branches: [[name: '*/master']], doGenerateSubmoduleConfigurations: false, extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'smart-check']], submoduleCfg: [], userRemoteConfigs: [[url: 'https://github.com/tsheth/DockerbaseDSSC.git']]])
            }
        }
        stage('Build') {
            steps{
                sh("docker build -t $SCAN_REGISTRY/$SCAN_REPOSITORY/$JOB_BASE_NAME:$BUILD_ID $WORKSPACE/smart-check")
            }
        }
        stage('Send to Repository') {
              steps{
                   script{
                      sh("docker login $SCAN_REGISTRY -u $ACR_CRED_USR -p $ACR_CRED_PSW")
                      sh("docker push $SCAN_REGISTRY/$SCAN_REPOSITORY/$JOB_BASE_NAME:$BUILD_ID")
                  }
            }    
                    
        }
        stage('Scan image with DSSC'){
            steps{
                withCredentials([
                    usernamePassword([
                        credentialsId: "azure-acr",
                        usernameVariable: "ACR_CRED_USR",
                        passwordVariable: "ACR_CRED_PSW",
                    ])
                ]){
                    smartcheckScan([
                        imageName: "${SCAN_REGISTRY}/${SCAN_REPOSITORY}/${JOB_BASE_NAME}:${BUILD_ID}",
                        smartcheckHost: "SMART_CHECK_SERVER",
                        insecureSkipTLSVerify: true,
                        smartcheckCredentialsId: "smart_check_jaws_world",
                        imagePullAuth: new groovy.json.JsonBuilder([
                            username: ACR_CRED_USR,
                            password: ACR_CRED_PSW,
                        ]).toString(),
                        findingsThreshold: new groovy.json.JsonBuilder([
                            malware: 1,
                            vulnerabilities: [
                                defcon1: 1,
                                critical: 3,
                                high: 4,
                            ],
                            contents: [
                                defcon1: 3,
                                critical: 3,
                                high: 3,
                            ],
                            checklists: [
                                defcon1: 2,
                                critical: 1,
                                high: 3,
                            ],
                        ]).toString(),
                    ])
                }
                
            }
        }
        stage('Certify Release')
        {
            steps{
                sh ("docker tag $SCAN_REGISTRY/$SCAN_REPOSITORY/$JOB_BASE_NAME:$BUILD_ID $SCAN_REGISTRY/$SCAN_REPOSITORY/$JOB_BASE_NAME:latest")
            }
        }
        stage('Deploy to Production')
        {
            steps{
                sh ("docker push $SCAN_REGISTRY/$SCAN_REPOSITORY/$JOB_BASE_NAME:latest")
                
                }
        }
            
        
    }
}
