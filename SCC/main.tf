variable "project_id" {
 default     = "qwiklabs-gcp-01-854d1dcc6f3a"
}


variable "zone" {
 default     = "us-central1-a"
}


variable "region" {
 default     = "us-central1"
}


# Cloud Storage bucket
resource "google_storage_bucket" "bucket" {
 name     = "compliance-data-${var.project_id}"
 location = var.region
 # Enforce uniform bucket-level access as a security best practice.
 uniform_bucket_level_access = true

 depends_on = [resource.null_resource.remediate_findings]
}


resource "google_storage_bucket_object" "object" {
 name    = "cepf_cis_12_report.csv"
 bucket  = google_storage_bucket.bucket.name
 content = "cepf_cis_12_report.csv"

 depends_on = [google_storage_bucket.bucket]
}


resource "null_resource" "remediate_findings" {
  triggers = {
  #  always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command     =  <<EOT
gcloud config set project ${var.project_id}


gcloud compute instances delete-access-config debian-server-vmtd  \
    --zone=${var.zone}

gcloud compute instances delete-access-config windows-server \
    --zone=${var.zone}



gcloud compute firewall-rules delete allow-ftp

gcloud compute firewall-rules delete allow-postgres

gcloud compute firewall-rules delete allow-rdp




sleep 60


gcloud scc muteconfigs create flow-logs-disabled --project=${var.project_id} --description="This is a
 test mute config" --filter="category=\"FLOW_LOGS_DISABLED\""


gcloud scc muteconfigs create audit-logging-disabled --project=${var.project_id} --description="This is a
 test mute config" --filter="category=\"AUDIT_LOGGING_DISABLED\""

gcloud scc muteconfigs create audit-logging-disabled --project=${var.project_id} --description="This is a
 test mute config" --filter="category=\"BUCKET_LOGGING_DISABLED\""

gcloud storage buckets remove-iam-policy-binding gs://${var.project_id}-public-bucket \
    --member=allUsers \
    --role=roles/storage.objectViewer
sleep 120

    EOT
   working_dir = path.module
}
}
