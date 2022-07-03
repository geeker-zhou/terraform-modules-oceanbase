variable "profile" {
  type     = string
  nullable = false
  default  = "default"
}

variable "region" {
  type     = string
  nullable = false
}

variable "instance_type" {
  type     = string
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

variable "root_volume" {
  type = object({
    size       = number
    type       = string
    iops       = number
    throughput = number
  })
  nullable = false

  validation {
    condition     = var.root_volume.iops >= 3000
    error_message = "The root_volume.iops is not Valid, volume iops should at least 5000 ."
  }

  validation {
    condition     = var.root_volume.size >= 100
    error_message = "The root_volume.size is not Valid, volume size should at least 100G ."
  }

  validation {
    condition     = contains(["gp3", "io2", "io3"], var.root_volume.type)
    error_message = "The root_volume.type is not Valid, volume type should be \"gp3\" or \"io2\" or \"io3\" ."
  }
}

variable "ebs_volume" {
  type = object({
    count      = number
    size       = number
    type       = string
    iops       = number
    throughput = number
  })
  nullable = false
  default = {
    count      = 1
    iops       = 3000
    size       = 100
    throughput = 125
    type       = "gp3"
  }
  validation {
    condition     = var.ebs_volume.count >= 1 && var.ebs_volume.count <= 10
    error_message = "The count of ebs_volume is not Valid, at least 1 ebs_volume should provided."
  }

  validation {
    condition     = var.ebs_volume.iops >= 3000
    error_message = "The ebs_volume.iops is not Valid, volume iops should at least 5000 ."
  }

  validation {
    condition     = var.ebs_volume.size >= 100
    error_message = "The ebs_volume.size is not Valid, volume size should at least 100G ."
  }

  validation {
    condition     = var.ebs_volume.throughput >= 125
    error_message = "The ebs_volume.throughput is not Valid, volume throughput should at least 125MBps ."
  }

  validation {
    condition     = contains(["gp3", "io2", "io3"], var.ebs_volume.type)
    error_message = "The ebs_volume.type is not Valid, volume type should be \"gp3\" or \"io2\" or \"io3\" ."
  }
}

