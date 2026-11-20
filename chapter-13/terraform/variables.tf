variable "atlas_public_key" {
  type        = string
  description = "MongoDB Atlas programmatic API public key"
  sensitive   = true
}

variable "atlas_private_key" {
  type        = string
  description = "MongoDB Atlas programmatic API private key"
  sensitive   = true
}

variable "atlas_org_id" {
  type        = string
  description = "MongoDB Atlas Organization ID"
}

variable "cluster_name" {
  type        = string
  description = "Atlas replica set cluster name"
  default     = "threatpulse-cloud-cluster"
}

variable "tier" {
  type        = string
  description = "Cluster instance tier (M0, M10, M20)"
  default     = "M0"
}

variable "region" {
  type        = string
  description = "AWS cloud deployment region"
  default     = "AP_SOUTH_1"
}

variable "db_username" {
  type        = string
  description = "Application database username"
  default     = "threatpulse_app"
}

variable "db_password" {
  type        = string
  description = "Application database password"
  sensitive   = true
  default     = "ThreatPulseSecurePass2026!"
}

variable "allowed_cidr" {
  type        = string
  description = "CIDR block permitted for cluster connection"
  default     = "0.0.0.0/0"
}

