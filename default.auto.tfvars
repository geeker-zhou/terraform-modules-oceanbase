### Enterprise
profile = "oceanbase"
region  = "cn-north-1"
## 16C 64G
instance_type = "m5.4xlarge"
## 16C 128G
# instance_type = "r5a.4xlarge"

ocp_package = {
  "antman" = "t-oceanbase-antman-1.4.2-20220430002909.alios7.x86_64.rpm"
  "ocp"    = "ocp331.tar.gz"
  "metadb" = "metaob-OB2277_OBP320_x86_20220429.tgz"
}

root_volume = {
  iops       = 3000
  size       = 100
  throughput = 125
  type       = "gp3"
}

ebs_volume = {
  count      = 2
  iops       = 3000
  size       = 200
  type       = "gp3"
  throughput = 125
}
