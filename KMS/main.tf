##

variable "project_id" {
 default     = "XXXX"
}


variable "suffix" {
 default     = "cepf" # It should be cymbal or ${var.suffix}-lab or lab-${var.suffix}
}


variable "zone" {
 default     = "XXXXXXXX"
}


variable "region" {
 default     =  "us-east1"
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
  project  = var.project_id
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
  #lifecycle {
   # prevent_destroy = true
  #}
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
