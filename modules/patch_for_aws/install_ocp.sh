#!/bin/bash
#****************************************************************#
# ScriptName: install_ocp.sh
# Author: zikang.lxj@alibaba-inc.com
# Create Date: 2018-10-11 11:35
# Modify Author: zikang.lxj@alibaba-inc.com
# Modify Date: 2018-10-11 11:35
# Function:
#***************************************************************#

kill $(pgrep "${0//./\\.}" | grep -v $$) &>/dev/null

base_dir=$(cd `dirname $0`;pwd)
source $base_dir/obcluster.conf
source $base_dir/common/utils.sh

DEBUG="${6:-"FALSE"}"
[ $DEBUG == "TRUE" ] && set -x


METADB_HOST=$1
METADB_PORT=$2
OCP_METADB_USERNAME=$3
OCPSERVER_HOSTNAME=$4
target_ip=$5
INIT_OCP="${7:-"FALSE"}"

CLUSTER_SYS_PASS=`get_sys_pass`
OCPMETA_TENANT_PASS=`get_meta_pass`
OCPMONITOR_TENANT_PASS=`get_monitor_pass`
CLUSTER_SYS_MONITOR_PASS=`get_sys_monitor_pass`

if [[ $OCP_METADB_USERNAME == ${OCP_METADB_USERNAME%#*} ]] ; then
    total_time=0
    while true; do
        res=$(mysql -h$target_ip -P$MYSQL_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -e "" 2>&1)
        if [[ $? -eq 0 ]] ; then
            antman_log "ob server is ready on host $target_ip"
            break
        else           
            sleep 30
            total_time=$(( total_time + 30 ))
            antman_log "waiting ob server ready on host $target_ip for ${total_time} Seconds"
            if [[ $total_time -gt 600 ]]; then
                antman_log "ANTMAN-501: timeout(${total_time} Seconds) on waiting ob server ready on host $target_ip" "ERROR"
                antman_log "Last error info: $res" "ERROR"
                exit 1
            fi
        fi
    done
else
    total_time=0
    while true; do
        res=$(mysql -h$OBPROXY_VIP -P$OBPROXY_VPORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -e "" 2>&1)
        if [[ $? -eq 0 ]] ; then
            antman_log "obproxy is ready"
            break
        else           
            sleep 30
            total_time=$(( total_time + 30 ))
            antman_log "waiting obproxy ready for ${total_time} Seconds"
            if [[ $total_time -gt 600 ]]; then
                antman_log "ANTMAN-502: timeout(${total_time} Seconds) on waiting obproxy ready" "ERROR"
                antman_log "Last error info: $res" "ERROR"
                exit 1
            fi
        fi
    done
fi


ocp_docker_name=$OCP_IMAGE_REPO:$OCP_IMAGE_TAG

docker_id=`docker ps -a --format "{{.ID}}\t{{.Image}}" | grep -w $ocp_docker_name| awk '{print $1}'`
if [[ -n $docker_id ]]; then
    antman_log "remove existed container: docker rm -f $docker_id"
    docker rm -f $docker_id
fi

if [ -n "$OCP_DOCKER_IMAGE_PACKAGE" ]; then
    antman_log "load docker image: docker load -i ${base_dir}/$OCP_DOCKER_IMAGE_PACKAGE"
    docker images $OCP_IMAGE_REPO:$OCP_IMAGE_TAG | grep $OCP_IMAGE_TAG
    if [ $? -ne 0 ]; then
        docker load -i ${base_dir}/$OCP_DOCKER_IMAGE_PACKAGE
    fi 
else
    antman_log "OCP_DOCKER_IMAGE_PACKAGE is empty, skip docker load."
fi

function replace_var_ocp24() {
    cat  > ${base_dir}/config/env_ocp.yaml <<@eof
OCP_METADB_HOST=$METADB_HOST
OCP_METADB_PORT=$METADB_PORT
OCP_METADB_USER=${OCP_METADB_USERNAME}
OCP_METADB_PASSWORD=${OCPMETA_TENANT_PASS}
OCP_METADB_DBNAME=${OCP_METADB_DBNAME}
OCP_MONITORDB_USER=${OCP_MONITORDB_USERNAME}
OCP_MONITORDB_PASSWORD=${OCPMONITOR_TENANT_PASS}
OCP_MONITORDB_DBNAME=${OCP_MONITOR_DBNAME}
OB_PORT=${OCP_PORT}
obcluster_name=${obcluster_name}
#JVM_HEAP_SIZE=12288
@eof
}

function init_ocp24_metadb() {
    docker_init_cmd="docker run --net host --workdir=/home/admin/ocp-init/src/ocp-init --entrypoint=python $ocp_docker_name create_metadb.py $METADB_HOST $METADB_PORT $OCP_METADB_USERNAME $OCPMETA_TENANT_PASS $OCP_METADB_DBNAME $OCP_MONITORDB_USERNAME $OCPMONITOR_TENANT_PASS $OCP_MONITOR_DBNAME"
    antman_log "init metadb: $docker_init_cmd"
    $docker_init_cmd
    init_docker_id=`docker ps -a --format "{{.ID}}\t{{.Image}}" | grep -w $ocp_docker_name | awk '{print $1}'`
    docker cp $init_docker_id:/home/admin/ocp-init/src/ocp-init/ocp-init.log ${base_dir}/logs > /dev/null 2>&1
    docker cp $init_docker_id:/home/admin/ocp-init/install/src/ocp.log ${base_dir}/logs > /dev/null 2>&1
    docker cp $init_docker_id:/home/admin/ocp-init/sqls ${base_dir}/logs > /dev/null 2>&1
    docker rm -f $init_docker_id
    #docker exec ${OCP_container_name} /bin/bash -c "cd /home/admin/ocp-init/src/ocp-init && python ./create_metadb.py $METADB_HOST $METADB_PORT $OCP_METADB_USERNAME $OCPMETA_TENANT_PASS $OCP_METADB_DBNAME $OCP_MONITORDB_USERNAME $OCPMONITOR_TENANT_PASS $OCP_MONITOR_DBNAME"
    #ob_version=$(mysql -h${METADB_HOST} -P${METADB_PORT} -uroot@sys -p"${CLUSTER_SYS_PASS}" -N -e "select value from oceanbase.__all_sys_parameter where name='min_observer_version'")
    timestamp_ns=$(date +%s%N)
    timestamp_us=$((timestamp_ns / 1000))
    # if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') == "TRUE" ]]; then
    #     mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e \
    #     "insert into ob_cluster(creator, name, ob_version, ob_cluster_id, type, rootserver_json, status, operate_status, compaction_status) 
    #     values('admin', '${obcluster_name}', '${ob_version}', '${cluster_id}', 'PRIMARY', '{\"ObRegion\":\"obcluster\",\"ObCluster\":\"${obcluster_name}\",\"ObRegionId\":${cluster_id},\"ObClusterId\":${cluster_id},\"Type\":\"PRIMARY\",\"timestamp\":${timestamp_us},\"RsList\":[{\"address\":\"${ZONE1_RS_IP}:${RPC_PORT}\",\"role\":\"LEADER\",\"sql_port\":${MYSQL_PORT}}],\"ReadonlyRsList\":[]}', 'RUNNING', 'NORMAL', 'IDLE');"
    # else
    #     mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e \
    #     "insert into ob_cluster(creator, name, ob_version, ob_cluster_id, type, rootserver_json, status, operate_status, compaction_status) 
    #     values('admin', '${obcluster_name}', '${ob_version}', '${cluster_id}', 'PRIMARY', '{\"ObRegion\":\"obcluster\",\"ObCluster\":\"${obcluster_name}\",\"ObRegionId\":${cluster_id},\"ObClusterId\":${cluster_id},\"Type\":\"PRIMARY\",\"timestamp\":${timestamp_us},\"RsList\":[{\"address\":\"${ZONE1_RS_IP}:${RPC_PORT}\",\"role\":\"LEADER\",\"sql_port\":${MYSQL_PORT}}, {\"address\":\"${ZONE2_RS_IP}:${RPC_PORT}\",\"role\":\"FOLLOWER\",\"sql_port\":${MYSQL_PORT}}, {\"address\":\"${ZONE3_RS_IP}:${RPC_PORT}\",\"role\":\"FOLLOWER\",\"sql_port\":${MYSQL_PORT}}],\"ReadonlyRsList\":[]}', 'RUNNING', 'NORMAL', 'IDLE');"
    # fi
    mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e "update config_properties set value='http://${target_ip}:${OCP_PORT}' where \`key\` = 'ocp.site.url';"
    mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e "update config_properties set value='${OCP_PORT}' where \`key\` = 'server.port';"
    if is_arm ; then
        mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e "update config_properties set value='aarch64' where \`key\` = 'ocp.operation.host.hardware-platform';"
    fi
}

IS_UPGRADE=${IS_UPGRADE:-FALSE}
version_in_db=$(mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -Nse"select value from config_properties where \`key\`='ocp.version'" 2>/dev/null)
if [[ -z "$version_in_db" ]]; then
    version_in_db=$(mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -Nse"select value from ocp2_sys_property where name='ocp.version'" 2>/dev/null)
fi
[[ -n "$version_in_db" ]] && [[ "$version_in_db" != "$OCP_VERSION" ]] && IS_UPGRADE=TRUE  # do not need init data and waiting for ready


echo ${OCP_VERSION} | grep -Eq "^2.[4-9]|^3"
if [[ $? -eq 0 ]]; then
    replace_var_ocp24
    if [[ $(echo $INIT_OCP | tr '[a-z]' '[A-Z]') == "TRUE" ]]; then
        if [[ "$IS_UPGRADE" = FALSE ]]; then
            init_ocp24_metadb
        else
            antman_log "In upgrade mode, old ocp version is $version_in_db, skip init ocp meta."
        fi
    fi
else
    source ${base_dir}/replace_var.sh ${base_dir}/config/env_ocp.yaml
fi

mkdir -p /home/admin/logs; setfacl -dm 'u:admin:rwx' /home/admin/logs; setfacl -dm 'u:500:rwx' /home/admin/logs
[[ "$IS_UPGRADE" = FALSE ]] && rm -rf /home/admin/logs/{ocp,obproxy,task} # 非升级场景清理日志
mkdir -p /home/admin/logs/{ocp,obproxy/log,obproxy/minidump}
chown admin:admin /home/admin/logs /home/admin/logs/{ocp,obproxy,obproxy/log,obproxy/minidump}
setfacl -Rm 'u:500:rwx' /home/admin/logs

docker_run_cmd_backup="docker run -d -it --name $OCP_CONTAINER_NAME --net=host --cpu-period 100000 --cpu-quota $OCP_DOCKER_CPUS"00000" --memory=$OCP_DOCKER_MEMORY --env-file=${base_dir}/config/env_ocp.yaml -v $PHYSICAL_BACKUP_DIR:/obbackup -v /home/admin/logs:/home/admin/logs --restart on-failure:5 $ocp_docker_name"
docker_run_cmd="docker run -d -it --name $OCP_CONTAINER_NAME --net=host --cpu-period 100000 --cpu-quota $OCP_DOCKER_CPUS"00000" --memory=$OCP_DOCKER_MEMORY --env-file=${base_dir}/config/env_ocp.yaml -v /home/admin/logs:/home/admin/logs --restart on-failure:5 $ocp_docker_name"

if [[ $BACKUP_ENABLE == "TRUE" ]]; then
    antman_log "start container: $docker_run_cmd_backup"
    eval $docker_run_cmd_backup
else
    antman_log "start container: $docker_run_cmd"
    eval $docker_run_cmd
fi

docker_id=`docker ps -a --format "{{.ID}}\t{{.Image}}" | grep -w $ocp_docker_name | awk '{print $1}'`
if [[ -z $docker_id ]] ; then
    antman_log "ANTMAN-503: failed to run ocp docker on host $target_ip" "ERROR"
    exit 1
fi


function get_compute_resource_id_ocp25() {
    local url=$1
    local payload=$2
    local resource_name=$3       # 用于过滤已存在的resource
    local user_pass=$4           # new default pass

    local ret=$(curl -s --user "$user_pass" --header 'Accept: application/json'  ${url} )  # local always return 0
    local contents
    contents=$(echo ${ret} | python -c "import json, sys; d=json.loads(raw_input()); print json.dumps(d['data']['contents']) if d['successful'] is True else sys.exit(1) ")
    if [ $? = 0 ]; then 
        exist_id=$(echo "$contents" | python -c "import json; d=json.loads(raw_input()); res=[ele for ele in d if ele['name'] == '${resource_name}']; print res[0]['id'] if res else None")
        if [ "$exist_id" = "None" ]; then
            resource_id=$(curl -s -X POST --user "$user_pass" --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$payload" ${url} | python -c "import json; d=json.loads(raw_input()); print d['data']['id']")
            [ "$resource_id" = "" ] && { antman_log "POST ${url}失败， payload: ${payload}, return ${resource_id}" "ERROR"; return 1; }
            echo $resource_id
        else
            echo $exist_id
        fi 
    else
        antman_log "GET ${url}失败, paylad ${payload}, return ${ret}" "ERROR"
        return 1
    fi
}

function import_host_and_cluster_ocp25() {
    local base_url=http://${target_ip}:${OCP_PORT}/api/v2
    local host_type_url=${base_url}/compute/hostTypes
    local region_url=${base_url}/compute/regions
    local idc_url=${base_url}/compute/idcs
    local credential_url=${base_url}/profiles/me/credentials?targetType=HOST
    local host_list_url=${base_url}/compute/hosts
    local prepare_host_url=${base_url}/compute/hosts/batchCreate
    local check_url=${base_url}/ob/clusters/takeOverPreCheck
    local takeover_url=${base_url}/ob/clusters/takeOver
    local cluster_list_url=${base_url}/ob/clusters

    
    local index=0
    ZONE_RS_IP_LIST=($ZONE1_RS_IP $ZONE2_RS_IP $ZONE3_RS_IP)
    ZONE_NAME_LIST=($ZONE1_NAME $ZONE2_NAME $ZONE3_NAME)
    ZONE_REGION_LIST=($ZONE1_REGION $ZONE2_REGION $ZONE3_REGION)
    ROOT_PASSWORD_LIST=($OBSERVER01_ROOTPASS $OBSERVER02_ROOTPASS $OBSERVER03_ROOTPASS)

    # 第一版ocp 2.5支持，与之前一致，不支持idc信息修改 但支持 region修改...，3.2以上更换默认密码
    local gt_320=$(echo ${OCP_VERSION} | python -c "import re; v=raw_input(); print re.match(r'\d\.\d\.\d', v) and v >= '3.2.0' ")
    if [ "$gt_320" = True ]; then
        user_pass=admin:aaAA11__
    else
        user_pass=admin:root
    fi

    for host_ip in ${ZONE_RS_IP_LIST[@]}; do
        zone_name=${ZONE_NAME_LIST[$index]}
        zone_region=${ZONE_REGION_LIST[$index]}
        root_passord=${ROOT_PASSWORD_LIST[$index]}

        antman_log "ALTER SYSTEM ALTER ZONE ${zone_name} set idc='${IDC_ROOM}';"
        mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -uroot@sys -p"${CLUSTER_SYS_PASS}" -Doceanbase -N -e "ALTER SYSTEM ALTER ZONE ${zone_name} set idc='${IDC_ROOM}';"
    
        # 添加机型
        host_type_id=$(get_compute_resource_id_ocp25  $host_type_url  '{"name":"METAOB_DOCKER"}'  "METAOB_DOCKER" "$user_pass") # hardcode, 命名方式不允许横线
        [ $? != 0 ] && exit 1
        # 添加region
        region_id=$(get_compute_resource_id_ocp25  $region_url  "{\"name\": \"${zone_region}\"}"   "$zone_region" "$user_pass")
        [ $? != 0 ] && exit 1
        # 添加idc
        idc_id=$(get_compute_resource_id_ocp25  $idc_url  "{\"name\":\"${IDC_ROOM}\",\"regionId\":${region_id} }"  "$IDC_ROOM" "$user_pass")
        [ $? != 0 ] && exit 1
        # 添加credentials
        credential_name="metaob_docker${index}_root"
        credential_id=$(get_compute_resource_id_ocp25  $credential_url  "{\"validate\":true,\"targetType\":\"HOST\",\"name\":\"${credential_name}\",\"description\":\"\",\"sshCredentialProperty\":{\"type\":\"PASSWORD\",\"username\":\"root\",\"passphrase\":\"${root_passord}\",\"hostIdList\":[]},\"obJdbcCredentialProperty\":{}}"  "$credential_name" "$user_pass")
        [ $? != 0 ] && exit 1
        # 添加主机, 特殊处理
        curl -s --user "$user_pass" -H 'Accept: application/json' -H 'Content-Type: application/json' "$host_list_url" | grep -q "\"innerIpAddress\":\"$host_ip\""
        if [ $? -eq 0 ]; then
            echo "server $host_ip already added."
        else
            local payload="{\"hostBasicDataList\":[{\"innerIpAddress\":\"${host_ip}\"}],\"sshPort\":2022,\"typeId\":${host_type_id},\"idcId\":${idc_id},\"kind\":\"DEDICATED_PHYSICAL_MACHINE\",\"credentialId\":${credential_id}}"  # hardcode 2022
            local ret=$(curl -s -X POST --user "$user_pass" --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$payload" ${prepare_host_url})
            echo ${ret} | python -c "import json, sys; d=json.loads(raw_input()); None if d['successful'] is True else sys.exit(1)"
            [ $? != 0 ] && { antman_log "POST ${prepare_host_url}失败， payload: ${payload}, return ${ret}" "ERROR"; exit 1; }
        fi
        ((index++))
    done
   
    (curl -s --user "$user_pass" -H 'Accept: application/json' -H 'Content-Type: application/json' "$cluster_list_url" | grep -q "\"name\":\"$obcluster_name\"") && { antman_log "cluster $obcluster_name is already taken over"; return 0; }
    # waite prepare host ready, 3mins is enough
    local rs_ip=$(mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -uroot@sys -p"${CLUSTER_SYS_PASS}" -Doceanbase -N -e "select svr_ip from __all_server where with_rootserver = 1")
    payload="{\"rootSysPassword\":\"${CLUSTER_SYS_PASS}\",\"saveToCredential\":true,\"address\":\"$rs_ip\",\"port\":${MYSQL_PORT}}"
    
    local wait_time=0
    while true; do
        if [ "$wait_time" -lt 180 ]; then
            antman_log "start takeOverPreCheck, already wait ${wait_time}s"
            curl -s -X POST --user "$user_pass" --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$payload" ${check_url} | python -c "import json, sys; d=json.loads(raw_input()); print d.get('data',{}).get('result',{}); None if d.get('data',{}).get('result',{}).get('valid') is True else sys.exit(1); "
            if [ $? = 0 ]; then
                antman_log "takeOverPreCheck success"
                break
            else    
                sleep 30
                wait_time=$((wait_time + 30))
            fi
        else
            antman_log "takeOverPreCheck timeout, failed" "ERROR"
            exit 1
        fi
    done

    # takeover cluster
    local ret=$(curl -s -X POST --user "$user_pass" --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$payload" ${takeover_url} )
    response=$(echo ${ret}| python -c "import json, sys; d=json.loads(raw_input()); print json.dumps(d) if d['successful'] is True else sys.exit(1)")
    [ $? != 0 ] && { antman_log "POST ${prepare_host_url}失败， payload: ${payload}, return ${ret}" "ERROR"; exit 1; }
    antman_log "takeover cluster through rs $rs_ip: $payload"
    
}

function import_meta_obcluster() {
    echo ${OCP_VERSION} | grep -Eq "^2\.5|^3"
    if [ $? = 0 ]; then
        import_host_and_cluster_ocp25

    else
        OCP_AGENT_VERSION=$(docker exec ocp /bin/bash -c "rpm -qa | grep ocp-agent")".rpm"
        OB_AGENT_VERSION=$(docker exec ocp /bin/bash -c "rpm -qa | grep ob-agent")".rpm"
        #mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e "update config_properties set value='${OCP_AGENT_VERSION}' where \`key\` = 'ocp.ocp-agent.version';"
        #mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -e "update config_properties set value='${OB_AGENT_VERSION}' where \`key\` = 'ocp.ob-agent.version';"
        local host_id_list=""
        local index=0
        ZONE_RS_IP_LIST=($ZONE1_RS_IP $ZONE2_RS_IP $ZONE3_RS_IP)
        ZONE_NAME_LIST=($ZONE1_NAME $ZONE2_NAME $ZONE3_NAME)
        ZONE_REGION_LIST=($ZONE1_REGION $ZONE2_REGION $ZONE3_REGION)
        HOSTNAME_LIST=("$METAOB1_HOSTNAME" "$METAOB2_HOSTNAME" "$METAOB3_HOSTNAME")  # install_ocp_remote.sh 生成的变量
        for host_ip in ${ZONE_RS_IP_LIST[@]}; do
            host_sm_name='METAOB'
            host_idc=${IDC_ROOM}
            host_name=$(_ssh ${host_ip} hostname 2>/dev/null) # oat允许连接失败，走传参
            [ "$host_name" = "" ] && host_name=${HOSTNAME_LIST[$index]}
            host_sn=${host_name}
            OCP_AGENT_VERSION=$(docker exec META_OB_ZONE_1 /bin/bash -c "rpm -qa | grep ocp-agent" | cut -d '-' -f 5-6 | cut -d '.' -f 1-3)
            ZONE_NAME=${ZONE_NAME_LIST[$index]}
            ZONE_REGION=${ZONE_REGION_LIST[$index]}
            antman_log "ALTER SYSTEM ALTER ZONE ${ZONE_NAME} set idc='${IDC_ROOM}';"
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -uroot@sys -p"${CLUSTER_SYS_PASS}" -Doceanbase -N -e "ALTER SYSTEM ALTER ZONE ${ZONE_NAME} set idc='${IDC_ROOM}';"
            import_host_body="{\"regionName\":\"${ZONE_REGION}\",\"hostTypeName\":\"${host_sm_name}-DOCKER\",\"idcName\":\"${host_idc}\",\"innerIpAddress\":\"${host_ip}\",\"kind\":\"DEDICATED_PHYSICAL_MACHINE\",\"serialNumber\":\"${host_sn}\",\"description\":\"OCP Machine\",\"sshPort\":\"${SSH_PORT}\",\"hostname\":\"${host_name}\",\"operatingSystem\":\"$(uname -r)\",\"status\":\"AVAILABLE\",\"hostAgent\":{\"version\":\"${OCP_AGENT_VERSION}\",\"installHome\":\"/home/admin/ocp_agent\",\"logHome\":\"/home/admin/ocp_agent/log\"}}"
            antman_log "import host: $import_host_body"
            import_host_ret=$(curl -s -X POST --user admin:root --header 'Accept: application/json' --header 'Content-Type: application/json' --data "${import_host_body}" "http://${target_ip}:${OCP_PORT}/api/v2/compute/hosts/import")
            antman_log "import host response: $import_host_ret"
            host_id=$(mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -N -e "select id from compute_host where inner_ip_address = '$host_ip';")
            if [[ $? -eq 0 && "$host_id" != "" ]]; then
                if [[ "$host_id_list" == "" ]]; then
                    host_id_list=$host_id
                else
                    host_id_list="$host_id_list,$host_id"
                fi
                OBPROXY_VERSION="obproxy-1.7.4-1894972.el7"
                # prevent installation of obproxy on ocp-obproxy host
                # antman_log "insert into compute_host_service (host_id, type, name, version) values ($host_id, 'OB_PROXY', 'obproxy', '${OBPROXY_VERSION}');"
                # mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -N -e "insert into compute_host_service (host_id, type, name, version) values ($host_id, 'OB_PROXY', 'obproxy', '${OBPROXY_VERSION}');"
                antman_log "import host $host_ip SUCCESS"
            else
                antman_log "import host $host_ip FAILED" "ERROR"
            fi
            ((index++))
        done
    
        local rs_ip=$(mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -uroot@sys -p"${CLUSTER_SYS_PASS}" -Doceanbase -N -e "select svr_ip from __all_server where with_rootserver = 1")
        import_cluster_body="{\"rootSysPassword\":\"${CLUSTER_SYS_PASS}\",\"saveToCredential\":true,\"address\":\"$rs_ip\",\"port\":${MYSQL_PORT},\"servers\":[$host_id_list]}"
        antman_log "import cluster through rs $rs_ip: $import_cluster_body"
        import_cluster_ret=$(curl -s -X POST --user admin:root -H "Content-Type:application/json" -d "$import_cluster_body" "http://${target_ip}:${OCP_PORT}/api/v2/ob/clusters/import")
        antman_log "import cluster response: $import_cluster_ret"
    fi
    
    
    sleep 10 #  wait task start
    max_wait_time=600
    wait_time_sum=0
    while true; do
        local cluster_status=$(mysql -h$METADB_HOST -P$METADB_PORT -u${OCP_METADB_USERNAME} -p${OCPMETA_TENANT_PASS} -D${OCP_METADB_DBNAME} -N -e "select status from ob_cluster where name = '$obcluster_name';")
        local cluster_status_ret=$?
        if [[ $cluster_status_ret -eq 0 && "$cluster_status" == "RUNNING" ]]; then
            antman_log "import obcluster and hosts SUCCESS"
            return 0
        elif [[ $cluster_status_ret -eq 0 && ("$cluster_status" == "IMPORTING" || "$cluster_status" == "TAKINGOVER") ]]; then
            antman_log "obcluster is still importing, wait 30s to check" "WARN"
            if [[ $wait_time_sum -ge $max_wait_time ]]; then
                antman_log "import obcluster failed, exceeds 10 minites, timeout!"
                exit 1
            else
                sleep 30
                wait_time_sum=$(( wait_time_sum+30 ))
            fi
        else
            antman_log "import obcluster and hosts FAILED, wait 30s to retry" "ERROR"
            if [[ $wait_time_sum -ge $max_wait_time ]]; then
                antman_log "import obcluster failed, exceeds 10 minites, timeout!"
                exit 1
            else
                sleep 30
                wait_time_sum=$(( wait_time_sum+30 ))
                break
            fi
        fi
    done
}

function is_ocp24_ready() {
    antman_log "check ocp api"
    curl -s "http://${target_ip}:${OCP_PORT}/api/v2/time" > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}
# upgrade do not need waiting
if [[ "$IS_UPGRADE" = TRUE ]]; then
   antman_log "In upgrade mode, ocp container is replaced, next you need to run ocp upgrade scripts manually."
   exit 1
fi

echo ${OCP_VERSION} | grep -Eq "^2.[4-9]|^3"
if [[ $? -eq 0 ]]; then
    if [[ $(echo $INIT_OCP | tr '[a-z]' '[A-Z]') == "TRUE" ]]; then
        total_time=30
        while true; do
            is_ocp24_ready
            if [[ $? -eq 0 ]]; then
                import_meta_obcluster
                break
            else
                sleep 30
                total_time=$(( total_time+30 ))
                if [[ $total_time -gt 600 ]] ; then
                    antman_log "Timeout( $(( total_time/60 )) Minites) on waiting ocp ready, URL=http://${target_ip}:${OCP_PORT}/api/v2/time" "ERROR"
                    exit 1
                fi
                antman_log "waiting ocp api to be ready on host ${target_ip} for $(( total_time/60 )) Minites"
            fi
        done
    fi
fi

total_time=30
while true; do
    curl -Ls --connect-timeout 5 "http://${target_ip}:${OCP_PORT}/services?Action=GetObProxyConfig&User_ID=admin&UID=alibaba" | grep successful > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        antman_log "ocp api is ready on host ${target_ip}"
        break
    else
        sleep 30
        total_time=$(( total_time+30 ))
        if [[ $total_time -gt 600 ]] ; then
            antman_log "ANTMAN-503: timeout( $(( total_time/60 )) Minites) on waiting ocp ready, URL=http://${target_ip}:${OCP_PORT}/services?Action=GetObProxyConfig&User_ID=admin&UID=alibaba" "ERROR"
            exit 1
        fi
        antman_log "waiting ocp to be ready on host ${target_ip} for $(( total_time/60 )) Minites"
    fi
done

