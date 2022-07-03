variable "aws_profile" {
  type     = string
  nullable = false
}

variable "aws_region" {
  type     = string
  nullable = false
}

variable "oceanbase_vpc" {
  type = object({
    cidr_block = string
  })
  nullable = false
}

variable "ocp_instance" {
  type = object({
    instance_type   = string
    public_ip  = string
    private_ip = string
    ssh_user        = string
    ssh_credential  = string
  })
  nullable = false
}

variable "ocp_package" {
  type = object({
    antman = string
    ocp    = string
    metadb = string
  })
  nullable = false
}
