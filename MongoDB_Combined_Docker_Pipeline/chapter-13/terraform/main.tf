terraform {
  required_version = ">= 1.5.0"
  required_providers {
    mongodbatlas = {
      source  = "mongodb/mongodbatlas"
      version = "~> 1.14.0"
    }
  }
}

provider "mongodbatlas" {
  public_key  = var.atlas_public_key
  private_key = var.atlas_private_key
}

# 1. Project Organization
resource "mongodbatlas_project" "threatpulse" {
  name   = "ThreatPulse-SOC-Chapter13"
  org_id = var.atlas_org_id
}

# 2. Cloud Replica Set Cluster (Free M0 or Dedicated M10)
resource "mongodbatlas_advanced_cluster" "soc_cluster" {
  project_id   = mongodbatlas_project.threatpulse.id
  name         = var.cluster_name
  cluster_type = "REPLICASET"

  replication_specs {
    region_configs {
      electable_specs {
        instance_size = var.tier
        node_count    = 3
      }
      provider_name = "AWS"
      region_name   = var.region
      priority      = 7
    }
  }
}

# 3. Application Database User (Scoped RBAC)
resource "mongodbatlas_database_user" "app_user" {
  username           = var.db_username
  password           = var.db_password
  project_id         = mongodbatlas_project.threatpulse.id
  auth_database_name = "admin"

  roles {
    role_name     = "readWrite"
    database_name = "threat_intel_db"
  }
}

# 4. Project IP Access Whitelist
resource "mongodbatlas_project_ip_access_list" "office_whitelist" {
  project_id = mongodbatlas_project.threatpulse.id
  cidr_block = var.allowed_cidr
  comment    = "ThreatPulse SOC Platform Authorized IP"
}
