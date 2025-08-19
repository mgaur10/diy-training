variable "project_id" {
 default     = "XXXXXXX"
}


variable "suffix" {
 default     = "lab-cepf" # It should be cymbal or cepf-lab or lab-cepf
}


variable "zone" {
 default     = "us-east1-c"
}


variable "region" {
 default     = "us-east1"
}

variable "attacker_vm_ip" {
 default     = "X.X.X.X" ## Get it from compute instance running in project #2
}


######## TASK-1 ################################################


# VPC
resource "google_compute_network" "vpc_network" {
  name                    =  "${var.suffix}-vpc"
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
  name          =  "${var.suffix}-vpc-subnet"
  provider      = google-beta
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.vpc_network.id
  project       = var.project_id
  private_ip_google_access = true
  
  #depends_on = [
  #  google_compute_network.base_network,
  #]
}




###################### DNS #####################################


resource "google_dns_managed_zone" "cloud_dns" {
  name       = "cloud-google-zone"
  dns_name   = "cloud.google.com."
  project    = var.project_id
  visibility = "private"
  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc_network.id
    }
  }
  depends_on = [
    google_compute_network.vpc_network,
  ]
}

resource "google_dns_record_set" "spf" {
  name         = "packages.${google_dns_managed_zone.cloud_dns.dns_name}"
  managed_zone = google_dns_managed_zone.cloud_dns.name
  type         = "A"
  ttl          = 300
  project      = var.project_id
  rrdatas      = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
  depends_on   = [google_dns_managed_zone.cloud_dns]
}


############################ IAM TAGs ##########################################

data "google_project" "project" {
project_id      = var.project_id
}

resource "google_tags_tag_key" "tag_key" {
  parent     = "projects/${data.google_project.project.project_id}"
  short_name = "${var.suffix}-tag"

  description = "For use with network firewall."
  purpose     = "GCE_FIREWALL"
  purpose_data = {
    network = "${var.project_id}/${var.suffix}-vpc"
  }
  depends_on = [
    google_compute_network.vpc_network,
  ]
}

resource "google_tags_tag_value" "tag_key_value" {
  parent      = "tagKeys/${google_tags_tag_key.tag_key.name}"
  short_name  = "${var.suffix}-www"
  description = "Tag for primary prod presentation."
  depends_on = [
    google_tags_tag_key.tag_key,
  ]
}

######################## Firewall ######################################

resource "google_compute_network_firewall_policy" "primary" {
  name = "${var.suffix}-firewall-policy"

  description = "Global network firewall policy "
  project     = var.project_id

  
}


resource "google_compute_network_firewall_policy_association" "primary" {
  name              = "association"
  attachment_target = google_compute_network.vpc_network.id
  firewall_policy   = google_compute_network_firewall_policy.primary.name
  project           = var.project_id
}


resource "google_compute_network_firewall_policy_rule" "deny_egress_ipv4_quarantine" {
  project         = var.project_id
  action          = "deny"
  description     = "deny-ingress-ipv4"
  direction       = "EGRESS"
  disabled        = false
  enable_logging  = true
  firewall_policy = google_compute_network_firewall_policy.primary.name
  priority        = 200000
  rule_name       = "deny-ingress-ipv4"
  #  target_service_accounts = ["emailAddress:my@service-account.com"]
  #target_secure_tags {
  #  name = "tagValues/${google_tags_tag_value.tag_key_value.name}"
  #}

  match {
    dest_ip_ranges = ["0.0.0.0/0"]


    layer4_configs {
      ip_protocol = "all"
    }
  }
  depends_on = [
    google_compute_network_firewall_policy.primary,
    google_compute_network_firewall_policy_association.primary,
#    google_tags_tag_value.tag_key_value,
  ]
}


# Deny ingress trafic
resource "google_compute_network_firewall_policy_rule" "deny_ingress_ipv4_quarantine" {
  project         = var.project_id
  action          = "deny"
  description     = "deny-ingress-ipv4"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = true
  firewall_policy = google_compute_network_firewall_policy.primary.name
  priority        = 200002
  rule_name       = "deny-ingress-ipv4"
  #  target_service_accounts = ["emailAddress:my@service-account.com"]
#  target_secure_tags {
#    name = "tagValues/${google_tags_tag_value.tag_key_value.name}"
#  }
  match {
    src_ip_ranges = ["0.0.0.0/0"]

    layer4_configs {
      ip_protocol = "all"
    }
  }
  depends_on = [
    google_compute_network_firewall_policy.primary,
    google_compute_network_firewall_policy_association.primary,
#    google_tags_tag_value.tag_key_value,
  ]
}

############################# Task 2 ########################################

########################## FIREWALL #######################################################

# Allow access from Identity-Aware Proxy
resource "google_compute_network_firewall_policy_rule" "allow_iap" {
  project         = var.project_id
  action          = "allow"
  description     = "Allow access from Identity-Aware Proxy"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = true
  firewall_policy = google_compute_network_firewall_policy.primary.name
  priority        = 11000
  rule_name       = "allow-iap"
  #  target_service_accounts = ["emailAddress:my@service-account.com"]
  target_secure_tags {
    name = "tagValues/${google_tags_tag_value.tag_key_value.name}"
  }



  match {
    src_ip_ranges = ["35.235.240.0/20"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = [22]
    }
  }
  depends_on = [
    google_compute_network_firewall_policy.primary,
    google_tags_tag_value.tag_key_value,
    google_compute_network_firewall_policy_association.primary,
  ]
}





# allow access from health check ranges
resource "google_compute_network_firewall_policy_rule" "allow_health_check_glb" {
  project         = var.project_id
  action          = "allow"
  description     = "Allow access from Health Check and GLB to Web Servers"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = true
  firewall_policy = google_compute_network_firewall_policy.primary.name
  priority        = 10000
  rule_name       = "allow-health-check"
  #  targetSecureTag   = true
  #  target_service_accounts = ["emailAddress:my@service-account.com"]
  target_secure_tags {
    name = "tagValues/${google_tags_tag_value.tag_key_value.name}"
  }

  match {
    src_ip_ranges = ["130.211.0.0/22", "35.191.0.0/16"]



    layer4_configs {
      ip_protocol = "tcp"
      ports       = [80]
    }
  }
  depends_on = [
    google_compute_network_firewall_policy.primary,
    google_tags_tag_value.tag_key_value,
    google_compute_network_firewall_policy_association.primary,
  ]
}


/*
# allow access from health check ranges
resource "google_compute_network_firewall_policy_rule" "allow_iap" {
  project         = var.project_id
  action          = "allow"
  description     = "Allow IAP access "
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = true
  firewall_policy = google_compute_network_firewall_policy.primary.name
  priority        = 10002
  rule_name       = "allow-iap-access"
  #  targetSecureTag   = true
  #  target_service_accounts = ["emailAddress:my@service-account.com"]
  target_secure_tags {
    name = "tagValues/${google_tags_tag_value.tag_key_value.name}"
  }

  match {
    src_ip_ranges = ["35.235.240.0/20"]



    layer4_configs {
      ip_protocol = "tcp"
      ports       = [22]
    }
  }
  depends_on = [
    google_compute_network_firewall_policy.primary,
    google_tags_tag_value.tag_key_value,
    google_compute_network_firewall_policy_association.primary,
  ]
}
*/


resource "google_compute_network_firewall_policy_rule" "allow_restricted_access_php" {
  project         = var.project_id
  action          = "allow"
  description     = "Allow access to install PHP Google Client Libraries"
  direction       = "EGRESS"
  disabled        = false
  enable_logging  = true
  firewall_policy = google_compute_network_firewall_policy.primary.name
  priority        = 110
  rule_name       = "allow-restricted-access"
  #  target_service_accounts = ["emailAddress:my@service-account.com"]
  target_secure_tags {
    name = "tagValues/${google_tags_tag_value.tag_key_value.name}"
  }

  match {
    dest_fqdns = ["deb.debian.org"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = [443]
    }
  }
  depends_on = [
    google_compute_network_firewall_policy.primary,
    google_compute_network_firewall_policy_association.primary,
  ]
}




################################# TASK 3 ########################################################

# Create a CloudRouter for secondary middleware subnet
resource "google_compute_router" "secondary_middleware_router" {
  project = var.project_id
  name    = "${var.suffix}-nat-router"
  region  = var.region
  network = google_compute_network.vpc_network.id

  bgp {
    asn = 64514
  }
  depends_on = [google_compute_network.vpc_network]
}

# Configure a CloudNAT for secondary middleware subnet
resource "google_compute_router_nat" "secondary_middleware_nats" {
  project                            = var.project_id
  name                               = "${var.suffix}-nat-config"
  router                             = google_compute_router.secondary_middleware_router.name
  region                             = google_compute_router.secondary_middleware_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"


  log_config {
    enable = true
    filter = "ALL"
  }
  depends_on = [
    google_compute_router.secondary_middleware_router,
    google_compute_subnetwork.vpc_subnetwork,
  ]
}





##################################### TASK 4 ####################################################

#Create the service Account for compute instances
resource "google_service_account" "def_ser_acc" {
  project      = var.project_id
  account_id   = "service-account"
  display_name = "Project Service Account"
  
}

# instance template
resource "google_compute_region_instance_template" "base_instance_template" {
  name    = "cepf-instance-template"
  project = var.project_id
region       = var.region
  provider = google-beta
  # tags     = ["http-server"]
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  network_interface {
    network    = google_compute_network.vpc_network.id
    subnetwork = google_compute_subnetwork.vpc_subnetwork.id
    #  access_config {
    # add external ip to fetch packages
    #   }
  }
  instance_description = "Basic compute instances"
  machine_type         = "e2-medium"
  can_ip_forward       = false


  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  // Create a new boot disk from an image
  disk {
    source_image = "debian-cloud/debian-12"
    auto_delete  = true
    boot         = true

  }
  resource_manager_tags = {
    "tagKeys/${google_tags_tag_key.tag_key.name}" = "tagValues/${google_tags_tag_value.tag_key_value.name}"
    } 

  # install apache server and serve a simple web page
  metadata_startup_script = file("${path.module}/scripts/startup.sh")
  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }


  depends_on = [
    google_compute_subnetwork.vpc_subnetwork,
    google_compute_router_nat.secondary_middleware_nats,
  ]
}


/*
resource "google_compute_instance_group" "juice_shop" {
  name        = "cepf-instance-group"
  description = "cepf-instance-group"
  project     = var.project_id
  instances = [
    "${google_compute_region_instance_template.base_instance_template.id}",
  ]
  named_port {
    name = "http"
    port = "80"
  }

  zone = var.zone

#  depends_on = [
#    null_resource.juice_shop_conatiner,
#  ]
}
*/

resource "google_compute_instance_group_manager" "juice_shop" {
  name = "cepf-instance-group"
  project     = var.project_id
  base_instance_name = "cepf-instance"
  zone               = var.zone

  version {
    instance_template  = google_compute_region_instance_template.base_instance_template.id
  }

  all_instances_config {
    metadata = {
      metadata_key = "metadata_value"
    }
    labels = {
      label_key = "label_value"
    }
  }

#  target_pools = [google_compute_target_pool.appserver.id]
  target_size  = 1

  named_port {
    name = "http"
    port = 80
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.juice_shop_health_check.id
    initial_delay_sec = 300
  }
}


# health check
resource "google_compute_health_check" "juice_shop_health_check" {
  project = var.project_id

  name     = "health-check"
  provider = google-beta
  #  http_health_check {
  #    port_specification = "USE_SERVING_PORT"
  #  }

  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2

  tcp_health_check {
    port = "80"
  }

  log_config {
    enable = true
  }

#  depends_on = [
#    time_sleep.wait_enable_service_api_armor,
#  ]
}



# backend service with custom request and response headers
resource "google_compute_backend_service" "waf_backend" {
  name    = "juice-shop-backend"
  project = var.project_id
security_policy = google_compute_security_policy.block_modsec_crs.id

  provider      = google-beta
  protocol      = "HTTP"
  port_name     = "http"
  timeout_sec   = 10
  enable_cdn    = false
  health_checks = [google_compute_health_check.juice_shop_health_check.id]


  backend {
    group                 = google_compute_instance_group_manager.juice_shop.instance_group
    balancing_mode        = "RATE"
    capacity_scaler       = 0.7
    max_rate_per_instance = 0.2
    #   port = 80
  }

  log_config {
    enable      = true
    sample_rate = 1
  }
  depends_on = [
   google_compute_instance_group_manager.juice_shop,

  ]

}

# url map
resource "google_compute_url_map" "juice_shop_url_map" {
  name            = "juice-shop-loadbalancer"
  provider        = google-beta
  default_service = google_compute_backend_service.waf_backend.id
  project         = var.project_id
  depends_on = [
    google_compute_backend_service.waf_backend,
  ]
}


# http proxy
resource "google_compute_target_http_proxy" "juice_shop_proxy" {
  name     = "juice-shop-proxy"
  provider = google-beta
  url_map  = google_compute_url_map.juice_shop_url_map.id
  project  = var.project_id
  depends_on = [
    google_compute_url_map.juice_shop_url_map,
  ]
}


# reserved IP address
resource "google_compute_global_address" "juice_shop" {
  provider     = google-beta
  name         = "juice-shop-external-ip"
  project      = var.project_id
  address_type = "EXTERNAL"
#  depends_on = [
#    time_sleep.wait_enable_service_api_armor,
#  ]
}


# forwarding rule
resource "google_compute_global_forwarding_rule" "juice_shop_rule" {
  name        = "cepf-forwarding-rule"
  provider    = google-beta
  ip_protocol = "TCP"
  port_range  = "80"
  target      = google_compute_target_http_proxy.juice_shop_proxy.id
  ip_address  = google_compute_global_address.juice_shop.id
  project     = var.project_id
  depends_on = [
    google_compute_global_address.juice_shop,
    google_compute_target_http_proxy.juice_shop_proxy,
  ]
}






# Cloud Armor Security Policy
resource "google_compute_security_policy" "block_modsec_crs" {
  name        = "cepf-policy"
  project     = var.project_id
  description = "Block OWASP Application Vulnerabilities"

  rule {
    action   = "deny(403)"
    priority = "8000"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('cve-canary', {'sensitivity': 3})"
      }
    }
    description = "block Log4j vulnerability attack"
  }

  rule {
    action   = "deny(403)"
    priority = "9000"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block sql injection attack"
  }

  rule {
    action   = "deny(403)"
    priority = "9001"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block local file inclusion"
  }

  rule {
    action   = "deny(403)"
    priority = "9002"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block remote code execution attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "9003"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block http protocol attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "9004"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sessionfixation-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block session fixation attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "9005"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block cross-site scripting attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "9006"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block remote file inclusion attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "9007"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('methodenforcement-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block method enforcement	attacks"
  }

  rule {
    action   = "deny(403)"
    priority = "9008"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('php-v33-stable', {'sensitivity': 3})"
      }
    }
    description = "block PHP injection attack attacks"
  }


  rule {
    action   = "deny(403)"
    priority = "9010"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('json-sqli-canary', {'sensitivity': 3})"
      }
    }
    description = "block JSON-based SQL injection bypass vulnerability attack"
  }

  rule {
    action   = "allow"
    priority = "10000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }

    description = "allow traffic from GCP Cloud shell and my IP"
  }

  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }

  rule {
    action   = "deny(404)"
    priority = "900"
    match {
      expr {
        expression = "request.path.matches('/admin.php')"
      }
    }
    description = "block Jadmin page"
  }


  rule {
    action   = "rate_based_ban"
    priority = "1000"

    rate_limit_options {
      rate_limit_threshold {
        count        = 5
        interval_sec = 60
      }

      ban_duration_sec = 300
      conform_action   = "allow"
      enforce_on_key   = "IP"
      exceed_action    = "deny(429)"

    }

    match {
      expr {
        expression = "true"
      }
    }
    description = "policy for rate limiting"
  }




  rule {
    action   = "deny(502)"
    priority = "500"
    match {
      expr {
        expression = "inIpRange(origin.ip, '${var.attacker_vm_ip}')"
      }
    }
    description = "attacker ip block"
  }


  #depends_on = [
  #  time_sleep.wait_enable_service_api_armor,
  #]
}


/*
resource "google_compute_security_policy_rule" "policy_rule" {
  security_policy = google_compute_security_policy.default.name
  description     = "new rule"
  priority        = 100
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = ["10.10.0.0/16"]
    }
  }
  action          = "allow"
  preview         = true
}


*/












/*
resource "google_compute_health_check" "autohealing" {
  name                = "autohealing-health-check"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 10 # 50 seconds

  http_health_check {
    request_path = "/healthz"
    port         = "8080"
  }
  


}


resource "google_compute_instance_group_manager" "instance_group_manager" {
  name               = "cepf-instance-group"
  instance_template  = "${google_compute_region_instance_template.base_instance_template.id}"
  base_instance_name = "cepf-instance-group"
  zone               = var.zone
  target_size        = "1"
  
 auto_healing_policies {
    health_check      = google_compute_health_check.autohealing.id
    initial_delay_sec = 300
  }
    named_port {
    name = "http"
    port = 80
  }
}
*/



#########################################################################################
#########################################################################################
#########################################################################################
#########################################################################################
resource "null_resource" "juice_shop_conatiner1" {

  triggers = {
    LB_IP = "${google_compute_global_address.juice_shop.address}"
    project            = var.project_id
  }
  provisioner "local-exec" {
    command     = <<EOT
#sleep 180
for i in {1..15}; do curl http://${google_compute_global_address.juice_shop.address}?data="user_data" ; done
sleep 90
for i in {1..15}; do curl http://${google_compute_global_address.juice_shop.address}/index.php?data=<script>alert("XSS+Attempt")</script>; done        
sleep 90
for i in {1..15}; do curl http://${google_compute_global_address.juice_shop.address}/admin.php; done
sleep 90
for i in {1..15}; do curl -s http://${google_compute_global_address.juice_shop.address}; done

    EOT
    working_dir = path.module
  }



  depends_on = [
    google_compute_global_forwarding_rule.juice_shop_rule
  ]
}




#########################################################################################
#########################################################################################



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
