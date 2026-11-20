output "cluster_id" {
  description = "MongoDB Atlas Cluster Identifier"
  value       = mongodbatlas_advanced_cluster.soc_cluster.cluster_id
}

output "standard_connection_string" {
  description = "Standard MongoDB Atlas SRV URI"
  value       = mongodbatlas_advanced_cluster.soc_cluster.connection_strings[0].standard_srv
  sensitive   = true
}

output "state_name" {
  description = "Deployment State"
  value       = mongodbatlas_advanced_cluster.soc_cluster.state_name
}
