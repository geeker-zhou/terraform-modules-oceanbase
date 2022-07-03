terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">= 3.1"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.15"
    }
  }

  required_version = ">= 1.2.0"
}
