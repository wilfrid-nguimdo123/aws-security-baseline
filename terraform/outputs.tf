output "vpc_id" {
  description = "Identifiant du VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "Identifiant du sous-réseau public"
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Identifiant du sous-réseau privé"
  value       = aws_subnet.private.id
}

output "security_group_id" {
  description = "Identifiant du Security Group durci"
  value       = aws_security_group.main.id
}

output "instance_id" {
  description = "Identifiant de l'instance EC2"
  value       = aws_instance.main.id
}

output "instance_public_ip" {
  description = "Adresse IP publique de l'instance EC2"
  value       = aws_instance.main.public_ip
}
