#!/bin/bash
#****************************************************************#
# ScriptName: install_OB_docker.sh
# Author: zikang.lxj@alibaba-inc.com
# Create Date: 2018-10-11 11:35
# Modify Author: zikang.lxj@alibaba-inc.com
# Modify Date: 2018-10-11 11:35
# Function: load OB docker, install OB rpm and start observer process
#***************************************************************#

kill $(pgrep "${0//./\\.}" | grep -v $$) &>/dev/null

base_dir=$(cd `dirname $0`;pwd)
source $base_dir/obcluster.conf
source $base_dir/common/utils.sh
OCPMETA_TENANT_PASS=`get_meta_pass`

zone=$1
svr_ip=$2
rootservice_list=$3
DEBUG="${4:-"FALSE"}"
[ $DEBUG == "TRUE" ] && set -x

observer_rpm="${base_dir}/$observer_rpm_version"
docker_name="$zone"
docker_image_name=$OB_IMAGE_REPO:$OB_IMAGE_TAG

if [ "$svr_ip" = "$ZONE1_RS_IP" ]; then
    password_root=$OBSERVER01_ROOTPASS
    password_admin=$OBSERVER01_ADMINPASS
elif [ "$svr_ip" = "$ZONE2_RS_IP" ]; then
    password_root=$OBSERVER02_ROOTPASS
    password_admin=$OBSERVER02_ADMINPASS
elif [ "$svr_ip" = "$ZONE3_RS_IP" ]; then
    password_root=$OBSERVER03_ROOTPASS
    password_admin=$OBSERVER03_ADMINPASS
elif ! [ -z "$5" -o -z "$6" ]; then
    password_root=$5
    password_admin=$6
else
    antman_log "can not get the root/admin password info!" "ERROR"
    exit 1
fi

dev_count=`ip a | grep -w $svr_ip | awk '{print $NF}' | wc -l`
if [ "$dev_count" != 1 ]; then
    antman_log "Can not get dev_name automatic, $dev_count device using $svr_ip " "ERROR"
    exit 1
fi
dev_name=`ip a | grep -w $svr_ip | awk '{print $NF}'`

docker_id=`docker ps -a --format "{{.ID}}\t{{.Image}}" | grep -w $docker_image_name | awk '{print $1}'`
if [[ -n $docker_id ]]; then
    antman_log "remove existed container: docker rm -f $docker_id"
    docker rm -f $docker_id
fi

if [ -n "$OB_DOCKER_IMAGE_PACKAGE" ]; then
    antman_log "load docker image: docker load -i ${base_dir}/$OB_DOCKER_IMAGE_PACKAGE"
    docker images $OB_IMAGE_REPO:$OB_IMAGE_TAG | grep $OB_IMAGE_TAG
    if [ $? -ne 0 ]; then
        docker load -i ${base_dir}/$OB_DOCKER_IMAGE_PACKAGE
    fi
else
    antman_log "OB_DOCKER_IMAGE_PACKAGE is empty, skip docker load."
fi

mkdir -p /home/admin/oceanbase
[ `ls -A /home/admin/oceanbase | wc -l` != 0 ] && { echo "/home/admin/oceanbase is not empty, please check!"; exit 1; }
[ -e "${PHYSICAL_DATA_DIR}/${obcluster_name}" ] && { echo "data dir $PHYSICAL_DATA_DIR/$obcluster_name exist, please check!"; exit 1; }
[ -e "${PHYSICAL_LOG_DIR}/${obcluster_name}" ] && { echo "log dir $PHYSICAL_LOG_DIR/$obcluster_name exist, please check!"; exit 1; }
[ `df ${PHYSICAL_DATA_DIR} |tail -1 | awk '{print ($4/$2*100 < a)}'  a=$DATAFILE_DISK_PERCENTAGE` = 1 ] && {  echo "data dir $PHYSICAL_DATA_DIR avail space less than ${DATAFILE_DISK_PERCENTAGE}%"; exit 1; }

if [[ "$OB_IMAGE_TAG" =~ "OBP" ]]; then
    observer_memory_limit=`expr ${OB_DOCKER_MEMORY%G} - 6`G  #保留6G给内置proxy及其余进程
    antman_log "RANDOM_PROXY_PASSWORD is $RANDOM_PROXY_PASSWORD"
    if [[ "$RANDOM_PROXY_PASSWORD" = TRUE ]]; then # read from env
        proxysys_pass=$(decode_pass proxysys)
        proxyro_pass=$(decode_pass proxyro)
        proxysys_pass_sha1=$(echo -n $proxysys_pass | sha1sum | awk '{print $1}')
        proxyro_pass_sha1=$(echo -n $proxyro_pass | sha1sum | awk '{print $1}')
        proxy_optstr="obproxy_sys_password=$proxysys_pass_sha1,observer_sys_password=$proxyro_pass_sha1,enable_strict_kernel_release=false,enable_metadb_used=false,enable_proxy_scramble=true,log_dir_size_threshold=10G,automatic_match_work_thread=false,work_thread_num=16,proxy_mem_limited=4G,client_max_connections=16384,enable_compression_protocol=false"
    else
        proxy_optstr="enable_strict_kernel_release=false,enable_metadb_used=false,enable_proxy_scramble=true,log_dir_size_threshold=10G,automatic_match_work_thread=false,work_thread_num=16,proxy_mem_limited=4G,client_max_connections=16384,enable_compression_protocol=false"

    fi
else
    observer_memory_limit=`expr ${OB_DOCKER_MEMORY%G} - 2`G  # 保留2G给其他进程
fi

[ -z "$OB_SYSTEM_MEMORY" ] && OB_SYSTEM_MEMORY=50G

docker_run_cmd_backup="docker run -d -it --cap-add SYS_RESOURCE --name $docker_name --net=host \
    -e OBCLUSTER_NAME=$obcluster_name  \
    -e DEV_NAME=$dev_name \
    -e ROOTSERVICE_LIST=\"$rootservice_list\" \
    -e DATAFILE_DISK_PERCENTAGE=$DATAFILE_DISK_PERCENTAGE \
    -e CLUSTER_ID=$cluster_id \
    -e ZONE_NAME=$zone \
    -e OBPROXY_PORT=$OBPROXY_PORT \
    -e MYSQL_PORT=$MYSQL_PORT \
    -e RPC_PORT=$RPC_PORT \
    -e OCP_VIP=$OCP_VIP \
    -e OCP_VPORT=$OCP_VPORT \
    -e app.password_root='${password_root}' \
    -e app.password_admin='${password_admin}' \
    -e OBPROXY_OPTSTR=\"$proxy_optstr\" \
    -e OPTSTR=\"cpu_count=$OB_DOCKER_CPUS,system_memory=$OB_SYSTEM_MEMORY,memory_limit=$observer_memory_limit,__min_full_resource_pool_memory=1073741824,_ob_enable_prepared_statement=false,memory_limit_percentage=90\" \
    --cpu-period 100000 \
    --cpu-quota $OB_DOCKER_CPUS"00000" \
    --cpuset-cpus "0-`expr $OB_DOCKER_CPUS - 1`" \
    --memory $OB_DOCKER_MEMORY \
    -v /home/admin/oceanbase:/home/admin/oceanbase \
    -v $PHYSICAL_LOG_DIR:/data/log1 \
    -v $PHYSICAL_DATA_DIR:/data/1 \
    -v $PHYSICAL_BACKUP_DIR:/obbackup \
    --restart on-failure:5 \
    $docker_image_name"

docker_run_cmd="docker run -d -it --cap-add SYS_RESOURCE --name $docker_name --net=host \
    -e OBCLUSTER_NAME=$obcluster_name  \
    -e DEV_NAME=$dev_name \
    -e ROOTSERVICE_LIST=\"$rootservice_list\" \
    -e DATAFILE_DISK_PERCENTAGE=$DATAFILE_DISK_PERCENTAGE \
    -e CLUSTER_ID=$cluster_id \
    -e ZONE_NAME=$zone \
    -e OBPROXY_PORT=$OBPROXY_PORT \
    -e MYSQL_PORT=$MYSQL_PORT \
    -e RPC_PORT=$RPC_PORT \
    -e OCP_VIP=$OCP_VIP \
    -e OCP_VPORT=$OCP_VPORT \
    -e app.password_root='${password_root}' \
    -e app.password_admin='${password_admin}' \
    -e OBPROXY_OPTSTR=\"$proxy_optstr\" \
    -e OPTSTR=\"cpu_count=$OB_DOCKER_CPUS,system_memory=$OB_SYSTEM_MEMORY,memory_limit=$observer_memory_limit,__min_full_resource_pool_memory=1073741824,_ob_enable_prepared_statement=false,memory_limit_percentage=90\" \
    --cpu-period 100000 \
    --cpu-quota $OB_DOCKER_CPUS"00000" \
    --cpuset-cpus "0-`expr $OB_DOCKER_CPUS - 1`" \
    --memory $OB_DOCKER_MEMORY \
    -v /home/admin/oceanbase:/home/admin/oceanbase \
    -v /root/t-oceanbase-antman/io_resource.conf:/home/admin/oceanbase/etc/io_resource.conf \
    -v $PHYSICAL_LOG_DIR:/data/log1 \
    -v $PHYSICAL_DATA_DIR:/data/1 \
    --restart on-failure:5 \
    $docker_image_name"

if [[ $BACKUP_ENABLE == "TRUE" ]]; then
    antman_log "start container: $docker_run_cmd_backup"
    eval $docker_run_cmd_backup
else
    antman_log "start container: $docker_run_cmd"
    touch /root/t-oceanbase-antman/io_resource.conf
    eval $docker_run_cmd
fi
