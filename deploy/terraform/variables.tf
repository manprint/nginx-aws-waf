variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-south-1"
}

variable "name_prefix" {
  description = "Prefix of every resource name"
  type        = string
  default     = "nginx-aws-waf"
}

variable "vpc_id" {
  description = "VPC of the nodes and of the central"
  type        = string
}

variable "nodes" {
  description = "Instances by name (the name becomes node_id): role node|central|all-in-one"
  type = map(object({
    role          = string
    instance_type = string
    subnet_id     = string
  }))
  validation {
    condition     = alltrue([for n in values(var.nodes) : contains(["node", "central", "all-in-one"], n.role)])
    error_message = "role must be node, central or all-in-one."
  }
  validation {
    condition     = alltrue([for k in keys(var.nodes) : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", k))])
    error_message = "node names must match ^[a-z0-9][a-z0-9-]{0,62}$ (they become node_id)."
  }
}

variable "node_cidrs" {
  description = "Source CIDRs of the WAF nodes: the only ones allowed on the central ingress (6000) and PKI API (6001)"
  type        = list(string)
}

variable "central_address" {
  description = "Name or IP the nodes use to reach the central (node.yaml central.address; must be in ingress.server_names/server_ips)"
  type        = string
}

variable "release_url" {
  description = "HTTPS URL of nginx-aws-waf-VERSION.tar.gz (scripts/build-release.sh)"
  type        = string
}

variable "ami_id" {
  description = "AMI (empty = latest Canonical Ubuntu 24.04 amd64)"
  type        = string
  default     = ""
}

variable "root_volume_gb" {
  description = "Root volume size (logs + raw logs + Vector disk buffer up to 2 GiB)"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Extra tags"
  type        = map(string)
  default     = {}
}
