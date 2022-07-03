provider "aws" {
  profile = "default"
  region  = "var.region"
}

data "aws_ami" "amazon" {
  most_recent = true
  filter {
    name   = "name"
    values = ["amzn2-ami-kernel-5.10-hvm*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  owners = ["amazon"]
}

resource "aws_default_vpc" "default_vpc" {}

resource "aws_default_security_group" "default" {
  vpc_id = aws_default_vpc.default_vpc.id

  ingress {
    description = "All ingress Traffic"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All egress Traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RSA key of size 4096 bits
resource "tls_private_key" "private_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# KeyPair for deploy OB
resource "aws_key_pair" "oceanbase_deployer" {
  key_name   = "ob-deployer-keypair"
  public_key = tls_private_key.private_key.public_key_openssh
}

# AMI


resource "aws_instance" "instance" {
  ami           = data.aws_ami.amazon.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.oceanbase_deployer.id
  #   iam_instance_profile = aws_iam_instance_profile.s3_access_profile.name


  root_block_device {
    volume_size = var.root_volume.size
    volume_type = var.root_volume.type
    iops        = var.root_volume.iops
    throughput  = var.root_volume.throughput
  }

  dynamic "ebs_block_device" {
    for_each = [for i in range(var.ebs_volume.count) : i]
    content {
      device_name = format("/dev/xvd%s", local.devices[ebs_block_device.key])
      iops        = var.ebs_volume.iops
      volume_size = var.ebs_volume.size
      volume_type = var.ebs_volume.type
      throughput  = var.ebs_volume.throughput
    }
  }

  tags = {
    Name = "ocp"
  }
}

module "ocp" {
  source = "./modules/ocp"

  aws_region  = var.region
  aws_profile = var.profile

  oceanbase_vpc = {
    cidr_block = aws_default_vpc.default_vpc.cidr_block
  }

  ocp_instance = {
    instance_type   = aws_instance.instance.instance_type
    public_ip  = aws_instance.instance.public_ip
    private_ip = aws_instance.instance.private_ip
    ssh_user        = "ec2-user"
    ssh_credential  = tls_private_key.private_key.private_key_openssh
  }

  ocp_package = var.ocp_package
}