## You know what to do !!!!!!!!!!!




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


variable "bucket_name" {
  default     = "XXXXXXXXXX"
}


provider "google" {
 project = var.project_id
 region  = var.region
}


data "google_client_config" "default" {}


provider "kubernetes" {
 host                   = "https://${google_container_cluster.primary.endpoint}"
 token                  = data.google_client_config.default.access_token
 cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
}


# GKE Cluster with Workload Identity
resource "google_container_cluster" "primary" {
 name                     = "${var.suffix}-cluster"
 location                 = var.zone
 # initial_node_count is ignored when remove_default_node_pool is true.
 remove_default_node_pool = true
initial_node_count = 1
 workload_identity_config {
   workload_pool = "${var.project_id}.svc.id.goog"
 }


 private_cluster_config {
   enable_private_nodes = true
   # 'false' makes the control plane accessible with an external IP, as required.
   enable_private_endpoint = false
   master_ipv4_cidr_block  = "172.16.0.16/28"
 }
}


resource "google_container_node_pool" "primary_nodes" {
 name       = "default-node-pool"
 cluster    = google_container_cluster.primary.name
 location   = google_container_cluster.primary.location
 node_count = 3


 node_config {
   machine_type = "e2-medium"
   shielded_instance_config {
     enable_secure_boot = true
   }
 }
}


# Cloud Storage bucket
resource "google_storage_bucket" "bucket" {
 name     = var.bucket_name
 location = var.region
 # Enforce uniform bucket-level access as a security best practice.
 uniform_bucket_level_access = true
}


resource "google_storage_bucket_object" "object" {
 name    = "sample-object.txt"
 bucket  = google_storage_bucket.bucket.name
 content = "This is a sample object in the bucket."
}


# Task 3 Resources
resource "kubernetes_namespace" "cepf_lab_ns1" {
 metadata {
   name = "${var.suffix}-ns1"
 }
 depends_on = [google_container_node_pool.primary_nodes]
}


resource "kubernetes_service_account" "cepf_lab_ksa1" {
 metadata {
   name      = "${var.suffix}-ksa1"
   namespace = kubernetes_namespace.cepf_lab_ns1.metadata.0.name
   annotations = {
     "iam.gke.io/gcp-service-account" = google_service_account.cepf_lab_gsa1.email
   }
 }
}


resource "google_service_account" "cepf_lab_gsa1" {
 account_id   = "${var.suffix}-gsa1"
 display_name = "CEPF Lab GSA1 (Storage Admin)"
 project      = var.project_id
}


resource "google_project_iam_member" "cepf_lab_gsa1" {
 project = var.project_id
 role    = "roles/storage.admin"
 member  = "serviceAccount:${google_service_account.cepf_lab_gsa1.email}"
}


resource "google_service_account_iam_binding" "workload_identity_binding" {
 service_account_id = google_service_account.cepf_lab_gsa1.name
 role               = "roles/iam.workloadIdentityUser"
 members = [
   "serviceAccount:${var.project_id}.svc.id.goog[${kubernetes_namespace.cepf_lab_ns1.metadata.0.name}/${kubernetes_service_account.cepf_lab_ksa1.metadata.0.name}]",
 ]
}




##### Once the first two tasks are completed, uncomment the below section. DO NOT UNCOMMENT TASK 4 YET!!!!!!!!!!!!!!!!!!!!!
/*
resource "kubernetes_manifest" "cepf_lab_workload_identity_pod" {
 manifest = {
   "apiVersion" = "v1",
   "kind"       = "Pod",
   "metadata"   = {
     "name"      = "${var.suffix}-workload-identity-pod"
     "namespace" = kubernetes_namespace.cepf_lab_ns1.metadata.0.name
   },
   "spec"       = {
     "serviceAccountName" = kubernetes_service_account.cepf_lab_ksa1.metadata.0.name
     "containers" = [
       {
         "name"    = "cloud-sdk"
         "image"   = "google/cloud-sdk:slim"
         "command" = ["sleep", "inf"]
       }
     ]
   }
 }
 depends_on = [google_service_account_iam_binding.workload_identity_binding]
}
*/


# Task 4 Resources


/*
resource "kubernetes_namespace" "cepf_lab_ns2" {
 metadata {
   name = "${var.suffix}-ns2"
 }
 depends_on = [google_container_node_pool.primary_nodes]
}


resource "google_service_account" "cepf_lab_gsa2" {
 account_id   = "${var.suffix}-gsa2"
 display_name = "CEPF Lab GSA2 (Storage Viewer)"
 project      = var.project_id
}


resource "google_storage_bucket_iam_member" "cepf_lab_gsa2_viewer" {
 bucket = google_storage_bucket.bucket.name
 role    = "roles/storage.objectViewer"
 member  = "serviceAccount:${google_service_account.cepf_lab_gsa2.email}"
}


resource "kubernetes_service_account" "cepf_lab_ksa2" {
 metadata {
   name      = "${var.suffix}-ksa2"
   namespace = kubernetes_namespace.cepf_lab_ns2.metadata.0.name
   annotations = {
     "iam.gke.io/gcp-service-account" = google_service_account.cepf_lab_gsa2.email
   }
 }
}


resource "google_service_account_iam_binding" "workload_identity_binding2" {
 service_account_id = google_service_account.cepf_lab_gsa2.name
 role               = "roles/iam.workloadIdentityUser"
 members = [
   "serviceAccount:${var.project_id}.svc.id.goog[${kubernetes_namespace.cepf_lab_ns2.metadata.0.name}/${kubernetes_service_account.cepf_lab_ksa2.metadata.0.name}]",
 ]
}


resource "kubernetes_manifest" "cepf_lab_workload_identity_pod2" {
 manifest = {
   "apiVersion" = "v1",
   "kind"       = "Pod",
   "metadata"   = {
     "name"      = "${var.suffix}-workload-identity-pod"
     "namespace" = kubernetes_namespace.cepf_lab_ns2.metadata.0.name
   },
   "spec"       = {
     "serviceAccountName" = kubernetes_service_account.cepf_lab_ksa2.metadata.0.name
     "containers" = [
       {
         "name"    = "cloud-sdk"
         "image"   = "google/cloud-sdk:slim"
         "command" = ["sleep", "inf"]
       }
     ]
   }
 }
 depends_on = [google_service_account_iam_binding.workload_identity_binding2]
}
*/








