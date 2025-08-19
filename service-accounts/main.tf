

variable "project_id" {
 default     = "UPDATE HERE"
}


variable "suffix" {
 default     = "XXXXXXXXXXX" # It should be cymbal or cepf-lab or lab-cepf
}


variable "zone" {
 default     = "XXXXXXXX"
}


variable "region" {
 default     = "XXXXXXXXX"
}


##################################TASK:1


#Create the service Account for compute instances
resource "google_service_account" "srv_acc" {
  provider     = google.service
  project      = var.project_id
  account_id   = "${var.suffix}-viewer"
  display_name = "${var.suffix}-viewer"
  #depends_on = [
  # time_sleep.wait_enable_service_api_armor,
  #]
}


resource "google_project_iam_member" "srv_acc_project" {
  project = var.project_id
  role    = "roles/compute.viewer"

  member = "serviceAccount:${google_service_account.srv_acc.email}"

}

resource "google_project_iam_member" "srv_acc_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"

  member = "serviceAccount:${google_service_account.srv_acc.email}"

}

# VPC
resource "google_compute_network" "vpc_network" {
  name                    = "${var.suffix}-vpc"
  provider                = google-beta
  auto_create_subnetworks = false
  project                 = var.project_id
  #depends_on = [
  # google_project_organization_policy.external_ip_access,
  #time_sleep.wait_enable_service_api_armor,
  #]

}



# backend subnet
resource "google_compute_subnetwork" "vpc_subnetwork" {
  name          = "${var.suffix}-subnet"
  provider      = google-beta
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.vpc_network.id
  project       = var.project_id
  #depends_on = [
  #  google_compute_network.base_network,
  #]
}


# Enable SSH through 
resource "google_compute_firewall" "allow_iap_proxy" {
  name      = "allow-iap-proxy"
  network   = google_compute_network.vpc_network.self_link
  project   = var.project_id
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
  depends_on = [
    google_compute_subnetwork.vpc_subnetwork,
  ]
}


resource "google_compute_instance" "default" {
  name         = "${var.suffix}-vm"
  machine_type = "n1-standard-2"
  zone         = var.zone
  project      = var.project_id
  tags         = ["foo", "bar"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  // Local SSD disk
  scratch_disk {
    interface = "SCSI"
  }

  network_interface {
    network    = google_compute_network.vpc_network.self_link
    subnetwork = google_compute_subnetwork.vpc_subnetwork.self_link

    access_config {
      // Ephemeral IP
    }
  }


  metadata = {
    enable-oslogin = "TRUE"
    SECRET         = "${var.suffix}-secret"
    SRV_AC_IMP     = "${google_service_account.srv_acc_imp.email}"
    PROJ_ID        = "${var.project_id}"
    ZONE           = "${var.zone}"
  }
  metadata_startup_script = file("${path.module}/scripts/startup.sh")
  #"sudo apt-get install jq  && curl --silent \"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/\" -H \"Metadata-Flavor: Google\" | jq . && sleep 120 && gcloud secrets create ${var.suffix}-secret  --impersonate-service-account ${google_service_account.srv_acc_imp.email}  && sleep 30 && curl -X GET \"https://compute.googleapis.com/compute/v1/projects/${var.project_id}/zones/${var.zone}/instances\" -H \"Authorization: Bearer $(gcloud auth print-access-token)\"  && gcloud compute instances list"
  service_account {
    scopes = ["cloud-platform"]
    email  = google_service_account.srv_acc.email
  }
}





##################################TASK:2

#Create the service Account for compute instances
resource "google_service_account" "srv_acc_imp" {
  provider     = google.service
  project      = var.project_id
  account_id   = "${var.suffix}-secret-admin-sa"
  display_name = "${var.suffix}-secret-admin-sa"
  #depends_on = [
  # time_sleep.wait_enable_service_api_armor,
  #]
}


resource "google_project_iam_member" "imp_srv_acc_project" {
  project = var.project_id
  role    = "roles/secretmanager.admin"

  member = "serviceAccount:${google_service_account.srv_acc_imp.email}"

}


resource "google_project_iam_audit_config" "project" {
  project = var.project_id
  service = "compute.googleapis.com"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
  audit_log_config {
    log_type = "DATA_READ"


  }
}





terraform {
  required_version = ">= 0.13"

  required_providers {
    google = {
    }

  }
}
provider "google" {
  alias                 = "service"
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}
