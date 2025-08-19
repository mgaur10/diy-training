##  Copyright 2023 Google LLC
##  
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##  
##      https://www.apache.org/licenses/LICENSE-2.0
##  
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.


##  This code creates PoC demo environment for Cloud Armor
##  This demo code is not built for production workload ##


#! /bin/bash
echo "1"
sudo apt-get update -y
echo "2"
sudo apt-get install jq 
echo "3"
sleep 30
echo "4"
 SECRET=$(curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/SECRET" -H "Metadata-Flavor: Google")
echo "5"
 SRV_AC_IMP=$(curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/SRV_AC_IMP" -H "Metadata-Flavor: Google")
echo "6"
 PROJ_ID=$(curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/PROJ_ID" -H "Metadata-Flavor: Google")
echo "7"
 ZONE=$(curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ZONE" -H "Metadata-Flavor: Google")
echo "8"
curl --silent "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/" -H "Metadata-Flavor: Google" 
echo "9"
sleep 120 
echo "10"
gcloud secrets create $SECRET  --impersonate-service-account $SRV_AC_IMP 
echo "11"
sleep 30 
echo "12"
curl -X GET "https://compute.googleapis.com/compute/v1/projects/$PROJ_ID/zones/$ZONE/instances" -H "Authorization: Bearer $(gcloud auth print-access-token)"  
echo "13"
gcloud compute instances list
echo "14"
 
