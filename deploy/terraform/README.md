# Terraform skeleton (AWS)

Skeleton only (D30): `make tf-validate` checks it with `hashicorp/terraform:1.17.2` in Docker;
this project never runs `apply`.

It creates:

- `aws_security_group.web`: 80/443 from anywhere (IPv4 and IPv6), for roles `node` and `all-in-one`;
- `aws_security_group.central`: 6000 (mTLS ingress) and 6001 (PKI API) only from `var.node_cidrs`,
  for roles `central` and `all-in-one`;
- one `aws_instance` per entry of `var.nodes` (name → `{role, instance_type, subnet_id}`; the name
  becomes `node_id`), Ubuntu 24.04, IMDSv2, encrypted gp3 root volume.

`user-data.sh.tftpl` installs Docker (`docker.io docker-compose-v2`), downloads the release from
`var.release_url`, runs `install-node.sh` and `wafctl node bootstrap --install-systemd`.
The certificate enrollment stays manual (one-time token): see `docs/multi-node.md`.

Example `terraform.tfvars`:

```hcl
vpc_id          = "vpc-0123456789abcdef0"
node_cidrs      = ["10.0.0.0/16"]
central_address = "central.internal.example.com"
release_url     = "https://downloads.example.com/nginx-aws-waf-0.5.0.tar.gz"
nodes = {
  central-1 = { role = "central", instance_type = "t3.large", subnet_id = "subnet-aaa" }
  web-1     = { role = "node", instance_type = "t3.medium", subnet_id = "subnet-bbb" }
}
```
