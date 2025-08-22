
variable "project_id" {
description = "The Google Cloud project ID to deploy resources into."
default     = "XXXXXXX"
}

variable "project2_id" {
description = "The Google Cloud project ID to deploy resources into."
default     = "XXXXXXXXXXX"
}



variable "suffix" {
description = "A suffix to append to resource names for uniqueness."
default     = "lab-cepf" # It should be cymbal or ${var.suffix}-lab or lab-${var.suffix}
}

variable "project1_zone" {
description = "The Google Cloud zone for zonal resources."
default     = "us-west1-b"
}


variable "project2_zone" {
description = "The Google Cloud zone for zonal resources."
default     = "us-central1-b"
}




variable "region" {
description = "The Google Cloud region for regional resources."
default     =  "us-west1"
}








# Configure the Google Cloud provider for Project 1
provider "google" {
 project = var.project_id
 region  = var.region
}


#################################################################
# Task 1: Create a key ring and a key in Cloud KMS
#################################################################


# Create a key ring named '${var.suffix}-key-ring' in the us-east1 location.
resource "google_kms_key_ring" "key_ring" {
 name     = "${var.suffix}-key-ring"
 location = var.region
}


# Create an empty, import-only key named '${var.suffix}-key'.
resource "google_kms_crypto_key" "crypto_key" {
 name     = "${var.suffix}-key"
 key_ring = google_kms_key_ring.key_ring.id


 # 'RAW_ENCRYPT_DECRYPT' corresponds to the "Raw symmetric encryption" purpose.
 purpose = "RAW_ENCRYPT_DECRYPT"


 # This flag creates an "empty" key, ready for the first version to be imported.
 # It also effectively restricts the key to import-only versions.
 skip_initial_version_creation = true
import_only = true
 version_template {
   # For the RAW_ENCRYPT_DECRYPT purpose, a specific algorithm must be set.
   # This must match the algorithm of the key material to be imported.
   algorithm        = "AES_256_GCM"
   protection_level = "HSM"
 }


 # It's a best practice to prevent accidental deletion of crypto keys.
 
}


#################################################################
# Task 2: Create an import job and share the wrapping key
#################################################################


# Create an import job named '${var.suffix}-import-job'.
resource "google_kms_key_ring_import_job" "import_job" {
 key_ring      = google_kms_key_ring.key_ring.id
 import_job_id = "${var.suffix}-import-job"


 # Set the import method and protection level as specified.
 import_method    = "RSA_OAEP_4096_SHA256"
 protection_level = "HSM"


 # Explicitly depend on the crypto key to ensure correct creation order.
 depends_on = [google_kms_crypto_key.crypto_key]
}

# Use the 'local_file' resource to save the public key
# This is the Terraform equivalent of the `--output-file` flag
resource "local_file" "wrapping_key" {
  # Access the public key's PEM content from the import job resource.
  # The 'public_key' attribute is a list, so we access the first element [0].
  content  = google_kms_key_ring_import_job.import_job.public_key[0].pem
  filename = "${path.module}/wrapping_key.pem"

  # Ensure this runs only after the import job is created
  depends_on = [google_kms_key_ring_import_job.import_job]
}

#################################################################
# Task 3: Encrypt sensitive data via local-exec
#################################################################


# This data source executes a script to SSH into the on-prem-instance,
# encrypt data, and return the results as a JSON object. This is a better
# approach than a null_resource with local-exec for capturing output.
# Wait delay after Task2
resource "time_sleep" "wait_enable_service" {
  create_duration  = "60s"

  depends_on = [
    google_kms_key_ring_import_job.import_job,
  ]
}


data "google_compute_default_service_account" "project1_defualt_srv_account" {
project = var.project_id
}


resource "google_project_iam_member" "project1" {
  project = var.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${data.google_compute_default_service_account.project1_defualt_srv_account.email}"
}


###################################NULL RESOURCE##########################
 resource "null_resource" "encrypt_data_on_vm" {
  triggers = {
  #  always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command     =  <<EOT

echo "### Task 3: Encrypting Data and Wrapping Key in Project 2 ###"
echo "### Switching context to Project 2: ${var.project2_id} ###"
gcloud config set project ${var.project2_id}

# Upload the wrapping key to the on-prem-instance VM
echo "Uploading wrapping key to ON_PREM_VM..."
gcloud compute scp ./"${local_file.wrapping_key.filename}" "on-prem-instance":~/ --zone "${var.project2_zone}"

echo "SSHing into on-prem-instance encryption and key wrapping..."
gcloud compute ssh "on-prem-instance" --zone  "${var.project2_zone}" -- '
    # Install required packages
    sudo apt-get update
    sudo apt-get install -y python3.9 python3-pip
    pip3 install cryptography

    # Generate a Data Encryption Key (DEK)
    echo "Generating Data Encryption Key (DEK)..."
    openssl rand 32 > $HOME/datakey.bin

    # Create the Python script to encrypt data
    echo "Creating encryption script..."
    cat << EOF > $HOME/encrypt_data.py
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import b64encode

# --- 1. Define Data and AAD ---
data = b"VERY SENSITIVE SECRET DATA"
aad = b"CEPFSecuredAAD"

# --- 2. Read Encryption Key ---
# Ensure you have a "datakey.bin" file with a 32-byte key in the same directory
try:
    with open("datakey.bin", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    print("Error: \"datakey.bin\" not found. Please generate a key file.")
    # For demonstration, we can generate a key if not found.
    # In a real application, you should handle this more securely.
    # key = AESGCM.generate_key(bit_length=256)
    # with open("datakey.bin", "wb") as key_file:
    #     key_file.write(key)
    # print("datakey.bin" created with a new key for demonstration.")
    exit()


# --- 3. Perform Encryption ---
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # Generate a random 12-byte IV (nonce)
ct = aesgcm.encrypt(nonce, data, aad) # Encrypt the data

# --- 4. Encode variables in Base64 and decode to strings for JSON ---
base64_ciphertext = b64encode(ct).decode("utf-8")
base64_iv = b64encode(nonce).decode("utf-8")
base64_aad = b64encode(aad).decode("utf-8")

# --- 5. Create the Python dictionary for the JSON payload ---
payload = {
  "ciphertext": base64_ciphertext,
  "initializationVector": base64_iv,
  "additionalAuthenticatedData": base64_aad
}

# --- 6. Write the dictionary to a JSON file ---
file_name = "payload.json"
with open(file_name, "w") as json_file:
    json.dump(payload, json_file, indent=2) # indent=2 makes the JSON file readable

print(f"Encryption successful. Output saved to \"{file_name}\"")
print("\n--- Content of payload.json ---")
print("Generated base64 AAD: {}\n".format(b64encode(aad)))
print("Generated base64 IV: {}\n".format(b64encode(nonce)))
print("Ciphertext base64 output : {}\n".format(b64encode(ct)))
# Print the content for verification
print(json.dumps(payload, indent=2))

EOF

    # Run the encryption script
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!! IMPORTANT: COPY THE FOLLOWING 3 VALUES FOR A LATER STEP !!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    python3.9 $HOME/encrypt_data.py

    # Wrap the DEK using the wrapping key
    echo "Wrapping the DEK with the public wrapping key..."

    
    echo "DEK wrapping complete."
    openssl pkeyutl \
      -encrypt \
      -pubin \
      -inkey $HOME/wrapping_key.pem \
      -in $HOME/datakey.bin \
      -out $HOME/wrapped_key.bin \
      -pkeyopt rsa_padding_mode:oaep \
      -pkeyopt rsa_oaep_md:sha256 \
      -pkeyopt rsa_mgf1_md:sha256
    echo "DEK wrapping complete."

'


# Download the wrapped key from the VM to the Cloud Shell
echo "Downloading wrapped key from ON_PREM_VM..."
gcloud compute scp "on-prem-instance":~/wrapped_key.bin ./ --zone "${var.project2_zone}"
    EOT
   working_dir = path.module
}
depends_on = [google_kms_key_ring_import_job.import_job,
time_sleep.wait_enable_service]
}




 resource "null_resource" "import_key_version" {
  triggers = {
  #  always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command     =  <<EOT
gcloud config set project ${var.project2_id}
gcloud compute scp "on-prem-instance":~/payload.json ./ --zone "${var.project2_zone}"
echo "### Task 3: Encrypting Data and Wrapping Key in Project 2 ###"
echo "###  Switching context back to Project 1: ${var.project_id} ###"
gcloud config set project ${var.project_id}
gcloud kms keys versions import \
    --import-job "${var.suffix}-import-job" \
    --keyring "${var.suffix}-key-ring" \
    --key "${var.suffix}-key" \
    --location "${var.region}" \
    --wrapped-key-file ./wrapped_key.bin \
    --project "${var.project_id}" \
    --algorithm "aes-256-gcm"
    EOT
   working_dir = path.module
}
depends_on = [ null_resource.encrypt_data_on_vm,
time_sleep.wait_enable_service]
}



#################### Task 5. Perform ciphertext decryption ####################

 resource "null_resource" "ciphertext_decryption" {
  triggers = {
  #  always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command     =  <<EOT
echo "###  Switching context back to Project 1: ${var.project_id} ###"
gcloud config set project ${var.project_id}
# Upload the payload.json file  to the lab VM
echo "Uploading payload.json  file to LAB_STUP..."
gcloud compute scp ./"payload.json" "lab-setup":~/ --zone "${var.project1_zone}"

gcloud compute ssh "lab-setup" --zone  "${var.project1_zone}" -- '
echo "https://cloudkms.googleapis.com/v1/projects/${var.project_id}/locations/${var.region}/keyRings/${var.suffix}-key-ring/cryptoKeys/${var.suffix}-key/cryptoKeyVersions/1:rawDecrypt" 
BASE64_DATA=$(curl -s "https://cloudkms.googleapis.com/v1/projects/${var.project_id}/locations/${var.region}/keyRings/${var.suffix}-key-ring/cryptoKeys/${var.suffix}-key/cryptoKeyVersions/1:rawDecrypt" --request "POST" --header "authorization:Bearer $(gcloud auth application-default print-access-token)" --header "content-type: application/json" --data @payload.json |jq -r ".plaintext")
echo $BASE64_DATA
echo $BASE64_DATA | base64 --decode
'
    EOT
   working_dir = path.module
}
depends_on = [ null_resource.encrypt_data_on_vm,
time_sleep.wait_enable_service,
resource.null_resource.import_key_version]
}

