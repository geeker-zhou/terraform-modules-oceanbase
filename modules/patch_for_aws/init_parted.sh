#!/bin/bash

function usage() {
    cat <<EOF
Usage:  $0 [OPTIONS]

Options:
  -h, --help                   Print help and exit
  -r, --role                   Set machine role, if not set, default is ocp
EOF
}

function is_nvme() {
  ls /dev/nvme* > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

role="ocp"

[ "$#" -eq 0 ] && { usage; exit 1; }
while true; do
    case $1 in
        -h | --help ) usage; exit 0;;
        -r | --role )
            if [ "$2" ]; then
                if [[ "$2" != "ob" && "$2" != "ocp" ]]; then
                    echo -e "incorrect machine role, must be [ ocp | ob  ].\n"; usage; exit 1
                fi
                role="$2"
                shift 2
            else
                echo -e "$1 requires an argument.\n"; usage; exit 1
            fi
            ;;
        -- ) shift; break ;;
        -?* ) echo -e "unknown flag: $1.\n"; usage; exit 1;;
        * ) break
    esac
done

log_size=`lsmem -b -n| grep 'Total online memory' | awk -F ':' '{print $2/1024/1024/1024 * 3}'| xargs printf '%.0f'`
disks=()
IFS=$'\n'
blks=`lsblk -abnlps -o +KNAME,FSTYPE,MOUNTPOINT /dev/xvd[f-p] | awk '{print $1";"$4";"$6";"$9";"$10;}'` 
for b in ${blks}; do
    OLDIFS=$IFS; IFS=$';'; f=(${b})
    ## data disk size > 500 GB, and type=disk, and mountpoint is blank
    if [[ ${f[2]} == "disk" && -z ${f[4]} ]]; then
        disks[${#disks[@]}]=${f[0]};
    fi
    IFS=${OLDIFS}
done
echo ${disks[*]}

### parted
for disk in ${disks[*]}; do
    parted -s ${disk} mklabel gpt mkpart primary 2048S 100%
    partprobe
    if is_nvme; then
      parts[${#parts[@]}]=${disk}p1
    else
      parts[${#parts[@]}]=${disk}1
    fi
done
echo ${parts[*]}

### LVM
yum -y install lvm2
pvcreate -f ${parts[*]}
vgcreate vgob ${parts[*]}

### OCP Volume
if [[ $role == "ocp" ]]; then
  lvcreate -L 100G -i ${#parts[@]} -I 128k --name docker vgob
fi

lvcreate -L ${log_size}G -i ${#parts[@]} -I 128k --name log vgob
lvcreate -l 100%FREE -i ${#parts[@]} -I 128k --name data vgob

if [[ $role == "ocp" ]]; then
  mkfs.ext4 -E lazy_itable_init=0,lazy_journal_init=0 /dev/vgob/docker
fi
mkfs.ext4 -E lazy_itable_init=0,lazy_journal_init=0 /dev/vgob/log 
mkfs.ext4 -E lazy_itable_init=0,lazy_journal_init=0 /dev/vgob/data


mkdir -p /data/log1 /data/1 /docker

if [[ $role == "ocp" ]]; then
  echo "/dev/mapper/vgob-docker /docker     ext4  defaults,noatime,nodiratime,nodelalloc,barrier=0  0  0" >> /etc/fstab
fi
echo "/dev/mapper/vgob-data   /data/1     ext4  defaults,noatime,nodiratime,nodelalloc,barrier=0  0  0" >> /etc/fstab
echo "/dev/mapper/vgob-log    /data/log1  ext4  defaults,noatime,nodiratime,nodelalloc,barrier=0  0  0" >> /etc/fstab

mount -a