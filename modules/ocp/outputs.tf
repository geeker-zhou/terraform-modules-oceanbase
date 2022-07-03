output "ocp_url" {
  description = "OCP access endporint, default USER/PASSWORD: root/aaAA11__"
  value       = "http://${var.ocp_instance.public_ip}:8081/"
}
