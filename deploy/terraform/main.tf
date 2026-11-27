# Skeleton only (D30): validated with `make tf-validate`, never applied by this project.

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

locals {
  web_roles     = ["node", "all-in-one"]
  central_roles = ["central", "all-in-one"]
  ami           = var.ami_id != "" ? var.ami_id : data.aws_ami.ubuntu.id
}

# Public web traffic (the WAF listens on 80/443 in host network mode)
resource "aws_security_group" "web" {
  name        = "${var.name_prefix}-web"
  description = "WAF nodes: HTTP/HTTPS from anywhere"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "web" {
  for_each = {
    http4  = { port = 80, cidr4 = "0.0.0.0/0", cidr6 = null }
    https4 = { port = 443, cidr4 = "0.0.0.0/0", cidr6 = null }
    http6  = { port = 80, cidr4 = null, cidr6 = "::/0" }
    https6 = { port = 443, cidr4 = null, cidr6 = "::/0" }
  }
  security_group_id = aws_security_group.web.id
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr4
  cidr_ipv6         = each.value.cidr6
}

# Central: mTLS ingress (6000) and PKI enrollment API (6001), only from the nodes
resource "aws_security_group" "central" {
  name        = "${var.name_prefix}-central"
  description = "WAF central: ingest and PKI only from the node CIDRs"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "central" {
  for_each = {
    for pair in setproduct([6000, 6001], var.node_cidrs) : "${pair[0]}-${pair[1]}" => { port = pair[0], cidr = pair[1] }
  }
  security_group_id = aws_security_group.central.id
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = strcontains(each.value.cidr, ":") ? null : each.value.cidr
  cidr_ipv6         = strcontains(each.value.cidr, ":") ? each.value.cidr : null
}

resource "aws_vpc_security_group_egress_rule" "all" {
  for_each          = { web = aws_security_group.web.id, central = aws_security_group.central.id }
  security_group_id = each.value
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "waf" {
  for_each      = var.nodes
  ami           = local.ami
  instance_type = each.value.instance_type
  subnet_id     = each.value.subnet_id
  vpc_security_group_ids = concat(
    contains(local.web_roles, each.value.role) ? [aws_security_group.web.id] : [],
    contains(local.central_roles, each.value.role) ? [aws_security_group.central.id] : [],
  )
  metadata_options {
    http_tokens = "required" # IMDSv2
  }
  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    node_id     = each.key
    role        = each.value.role
    central     = var.central_address
    release_url = var.release_url
  })
  user_data_replace_on_change = false
  tags                        = merge(var.tags, { Name = "${var.name_prefix}-${each.key}", WafRole = each.value.role })
}
