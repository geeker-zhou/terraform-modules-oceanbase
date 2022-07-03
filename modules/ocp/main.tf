provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region
}

locals {
  antman_image = var.ocp_package.antman
  ocp_image    = var.ocp_package.ocp
  metadb_image = var.ocp_package.metadb
  connect_type = "ssh"
  sudo_user = var.ocp_instance.ssh_user
  root_user = "root"
}

data "aws_ec2_instance_type" "ocp_instance_type" {
  instance_type = var.ocp_instance.instance_type

  ### Terraform > V1.2.0
  lifecycle {

    postcondition {
      condition     = self.default_vcpus >= 16 && self.memory_size >= 64 * 1024
      error_message = "The EC2 vCPUs must be greater than 16, Memory must be greater than 64G. \n${var.ocp_instance.instance_type}: \nvCPUs=${self.default_vcpus} \nMemory=${self.default_vcpus * 1024}G"
    }

  }
}

resource "null_resource" "init_ssh_key" {

  connection {
    type        = local.connect_type
    user        = local.sudo_user
    private_key = var.ocp_instance.ssh_credential
    host        = var.ocp_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "echo ${timestamp()} : save_key >> ./terraform.log",
      "echo '${var.ocp_instance.ssh_credential}'  > ./.ssh/id_rsa",
      "chmod 600 ./.ssh/id_rsa",
      "sudo /bin/cp -f ./.ssh/authorized_keys /root/.ssh/authorized_keys",
      "sudo /bin/cp -f ./.ssh/id_rsa /root/.ssh/id_rsa",
      "sudo sed -i s/^#PermitRootLogin/PermitRootLogin/g /etc/ssh/sshd_config",
      "sudo sed -i s/^#ClientAliveInterval\\ 0/ClientAliveInterval\\ 60/g /etc/ssh/sshd_config",
      "sudo sed -i s/^#ClientAliveCountMax/ClientAliveCountMax/g /etc/ssh/sshd_config",
      "sudo systemctl restart sshd",
    ]
  }

  triggers = {
    key_id = format("${var.ocp_instance.public_ip}-%d", 1),
  }

  depends_on = [
    data.aws_ec2_instance_type.ocp_instance_type
  ]

}

resource "null_resource" "init_ocp_image" {
  connection {
    type        = local.connect_type
    user        = local.root_user
    private_key = var.ocp_instance.ssh_credential
    host        = var.ocp_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "echo ${timestamp()} : upload antman>> ./terraform.log",
      "mkdir -p /${local.root_user}/oceanbase/",
      "aws --region ${var.aws_region} s3 cp s3://oceanbase /${local.root_user}/oceanbase/ --recursive > /dev/null"
    ]
  }

  # provisioner "file" {
  #   source      = "../image/"
  #   destination = "./oceanbase/"
  # }

  provisioner "file" {
    source      = "../patch_for_aws/"
    destination = "./oceanbase/"
  }

  triggers = {
    instance_id = format("${var.ocp_instance.public_ip}-%d", 2)
  }

  depends_on = [
    null_resource.init_ssh_key
  ]

}

resource "null_resource" "init_ocp_instance" {
  connection {
    type        = local.connect_type
    user        = local.root_user
    private_key = var.ocp_instance.ssh_credential
    host        = var.ocp_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "echo ${timestamp()} : init ocp host >> ./terraform.log",
      "sudo yum -y update > /dev/null",
      "sudo yum -y install oceanbase/${local.antman_image}",
      "sudo /bin/cp -rf ./oceanbase/* t-oceanbase-antman/",
      "/bin/bash ./t-oceanbase-antman/init_parted.sh -r ocp",
      "cd ./t-oceanbase-antman/clonescripts",
      "./clone.sh -u",
      "./clone.sh -m -r ocp",
      "./clone.sh -i",
      "./clone.sh -c -r ocp",
      "echo -e 'maxslewrate 500\nallow ${var.oceanbase_vpc.cidr_block}\nlocal stratum 10' >> /etc/chrony.conf",
      "systemctl restart chronyd"
    ]
  }

  triggers = {
    instance_id = format("${var.ocp_instance.public_ip}-%d", 1)
  }

  depends_on = [
    null_resource.init_ocp_image
  ]
}

resource "null_resource" "install_ocp" {
  connection {
    type        = local.connect_type
    user        = local.root_user
    private_key = var.ocp_instance.ssh_credential
    host        = var.ocp_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "echo ${timestamp()} : install ocp and metadb>> ./terraform.log",
      "cd /${local.root_user}/t-oceanbase-antman/",
      "docker load -i ${local.metadb_image} > /dev/null",
      "docker load -i ${local.ocp_image} > /dev/null",
      "sed -i '/^ZONE1_RS_IP=/cZONE1_RS_IP=${var.ocp_instance.private_ip}' obcluster.conf",
      "sed -i '/^OB_DOCKER_IMAGE_PACKAGE=/cOB_DOCKER_IMAGE_PACKAGE=${local.metadb_image}' obcluster.conf",
      "sed -i \"/^OB_IMAGE_REPO=/cOB_IMAGE_REPO=`docker images | grep ob | awk '{print $1}'`\" obcluster.conf",
      "sed -i \"/^OB_IMAGE_TAG=/cOB_IMAGE_TAG=`docker images | grep ob | awk '{print $2}'`\" obcluster.conf",
      "sed -i '/^OCP_DOCKER_IMAGE_PACKAGE=/cOCP_DOCKER_IMAGE_PACKAGE=${local.ocp_image}' obcluster.conf",
      "sed -i \"/^OCP_IMAGE_REPO=/cOCP_IMAGE_REPO=`docker images | grep ocp | awk '{print $1}'`\" obcluster.conf",
      "sed -i \"/^OCP_IMAGE_TAG=/cOCP_IMAGE_TAG=`docker images | grep ocp | awk '{print $2}'`\" obcluster.conf",
      "sed -i '/^OB_DOCKER_CPUS=/cOB_DOCKER_CPUS=${data.aws_ec2_instance_type.ocp_instance_type.default_vcpus > 16 ? 16 : data.aws_ec2_instance_type.ocp_instance_type.default_vcpus}' obcluster.conf",
      "sed -i '/^OB_DOCKER_MEMORY=/cOB_DOCKER_MEMORY=${data.aws_ec2_instance_type.ocp_instance_type.memory_size / 1024 > 128 ? 128 : data.aws_ec2_instance_type.ocp_instance_type.memory_size / 1024}G' obcluster.conf",
      "bash install.sh -i 1-8",
    ]
  }

  triggers = {
    instance_id = format("${var.ocp_instance.public_ip}-%d", 1)
  }

  depends_on = [
    null_resource.init_ocp_instance
  ]
}

