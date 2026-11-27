output "instances" {
  description = "Instance id, role and private/public IPs by node name"
  value = {
    for k, i in aws_instance.waf : k => {
      id         = i.id
      role       = var.nodes[k].role
      private_ip = i.private_ip
      public_ip  = i.public_ip
    }
  }
}

output "security_groups" {
  value = { web = aws_security_group.web.id, central = aws_security_group.central.id }
}
