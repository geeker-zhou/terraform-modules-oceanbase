#!/bin/bash
#****************************************************************#
# ScriptName: install.sh
# Author: zikang.lxj@alibaba-inc.com
# Create Date: 2018-10-11 11:35
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2019-03-27 00:00
# Function:
#***************************************************************#

DEBUG=FALSE
VERSION=1.4.2
INSTALL_STEPS=''
CLEAR_STEPS=''
MAX_STEP=8
base_dir=$(cd `dirname $0`;pwd)
CONF=$base_dir/obcluster.conf
source $base_dir/common/utils.sh
LOG_DIR="$base_dir/logs"
[ -d $LOG_DIR ] || mkdir -p $LOG_DIR
main_log="$LOG_DIR/antman_main.log"
progname=$(basename $0)

function usage() {
    cat <<EOF
NOTE:
  Please generate config file with init_obcluster_conf.sh before run this script.
  Script will read SSH_AUTH, SSH_USER, SSH_PORT, SSH_PASSWORD, SSH_KEY_FILE from env if exist
  SSH_AUTH can be set either "password" or "pubkey"
  SSH_KEY_FILE is take effect only when SSH_AUTH=pubkey
  If SSH_USER is not "root", make sure the user can execute [sudo bash] without password and /etc/sudoers has no requiretty setting.
  The default value is:
  SSH_AUTH=password SSH_USER=root SSH_PORT=22 SSH_PASSWORD='' SSH_KEY_FILE=/root/.ssh/id_rsa

Usage:  $0 [OPTIONS]

Options:
  -h, --help                   Print help and exit
  -d, --debug                  Print debug information
  -V, --version                Print version
  -i, --install-steps string   For example 1,3-5,7-
  -c, --clear-steps string     For example 1,3-5,7-
  -r, --replace  product_name old_repo_tag   For example:  odc reg.docker.alibaba-inc.com/oceanbase/odc-server:3.2.0
  -f, --config-file string     Read in a config file
  -l, --load-balance           Load balance mode

Steps:
    1. check ssh authorization
    2. install load balancer (default: dns for clustered ocp, none for single ocp)
    3. install ob server
    4. init ocp metadb
    5. install temp OCP
    6. install obproxy
    7. install OCP
    8. POSTCHECK
    9. install OMS (optional)
    10. install ODC (optional)
    11. install OCP Grafana (optional)
    12. install OCP Opensearch (optional)

EOF
}

function parse_steps(){
    local steps_str="${1//,/ }"
    local type="${2:-"INSTALL"}"
    local steps=''
    for str in $steps_str
    do
        if [[ $str =~ ^[1-9][0-9]*$ ]] ; then
            steps="$steps $str"
        elif [[ $str =~ ^[1-9][0-9]*-$ ]] ; then
            local begin=${str//-/}
            local end=$MAX_STEP
            if [[ $begin -gt $end ]] ; then
                antman_log "ANTMAN-005: arg error: $str (start step great than $STEPS)" "ERROR"
                exit 1
            fi
            steps="$steps $(seq $begin $end)"
        elif [[ $str =~ ^[1-9][0-9]*-[1-9][0-9]*$ ]] ; then
            local begin="${str%-*}"
            local end="${str#*-}"
            if [[ $begin -gt $end ]] || [[ $end -gt $MAX_STEP ]]; then
                antman_log "ANTMAN-005: arg error: $str (not meet start_step <= end_step <= $MAX_STEP )" "ERROR"
                exit 1
            fi
            steps="$steps $(seq $begin $end)"
        else
            antman_log "ANTMAN-006: arg error: $str (Unknown format)" "ERROR"
            exit 1
        fi
    done
    local STEPS=''
    if [[ $type == "CLEAR" ]] ; then
        STEPS=$(for str in $steps
        do
            echo $str
        done | sort -urn)
        CLEAR_STEPS="$(echo $STEPS)"
    else
        STEPS=$(for str in $steps
        do
            echo $str
        done | sort -un)
        INSTALL_STEPS="$(echo $STEPS)"
    fi
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

while true; do
    case $1 in
        -h | --help ) usage; exit 0;;
        -d | --debug ) DEBUG=TRUE; shift ;;
        -V | --version ) echo -e "$0 ($0 $VERSION)\nCopyright (c) 2007-2019 Alipay Inc."; exit 0;;
        -i | --install-steps )
            if [ "$2" ]; then
                parse_steps $2 INSTALL; shift 2
            else
                echo -e "$1 requires an argument.\n"; usage; exit 1
            fi
                ;;
        -c | --clear-steps )
            if [ "$2" ]; then
                parse_steps $2 CLEAR; shift 2
            else
                echo -e "$1 requires an argument.\n"; usage; exit 1
            fi
                ;;
        -f | --config-file )
            if [ "$2" ]; then
                CONF="$2"; shift 2
            else
                echo -e "$1 requires an argument.\n"; usage; exit 1
            fi
            ;;
        -l | --load-balance )
            if [[ "$2" == "dns" || "$2" == "nlb" || "$2" == "f5" || "$2" == "none" ]]; then
                LB_MODE="$2"; shift 2
            else
                echo -e "$1 requires an argument: [ nlb | dns | f5 | none ]\n"; usage; exit 1
            fi
            ;;
        -r | --replace )
            if [[ "$2" == "ocp" ]] || [[ "$2" == "odc" ]] || [[ "$2" == "oms" ]]; then
                REPLACE_PRODUCT="$2"
                if [[ -n "$3" ]]; then
                    [[ "$3" =~ : ]] || { echo "old product's repo_tag is not valid!"; usage; exit 1; }
                    OLD_PRODUCT_REPO_TAG=$3
                    shift 3
                else
                    echo "need old product's repo_tag as parameter"; usage; exit 1;
                fi
            else
                echo -e "product can only be [ ocp | odc | oms ]\n"; usage; exit 1
            fi
            ;;
        -- ) shift; break ;;
        -?* ) echo -e "unknown flag: $1.\n"; usage; exit 1;;
        * ) break
    esac
done

if [[ $DEBUG == "TRUE" ]]; then
    export PS4='+${BASH_SOURCE}:${LINENO}:${FUNCNAME[0]} '
    set -x
fi

echo "run $progname with DEBUG=$DEBUG, INSTALL_STEPS=$INSTALL_STEPS CLEAR_STEPS=$CLEAR_STEPS CONFIG_FILE=$CONF" | tee -a $main_log
if [ -f $CONF ] ; then
    [ "$CONF" = "$base_dir/obcluster.conf" ] || cp -f $CONF $base_dir/obcluster.conf
    check_upper_conf $base_dir/obcluster.conf
    (cat $base_dir/obcluster.conf | grep "^cluster_id" | grep "timestamp") && sed -i "/^cluster_id=/ccluster_id=`date +"%s"`" $base_dir/obcluster.conf
    source $base_dir/obcluster.conf
else
    antman_log "ANTMAN-004: config file $CONF doesn't exist! Please generate config file with init_obcluster_conf.sh before run this script!" "ERROR"
    exit 1
fi

function start_antman_api_service() {
    if is_arm; then
        antman_log "installation is on ARM, use antman_api_arm instead"
        antman_api_binary="antman_api_arm"
    else
        antman_api_binary="antman_api"
    fi

    api_pid=$(ps -ef | grep "$base_dir/antman_api/$antman_api_binary" | grep -v grep | awk '{print $2}')
    if [[ "$api_pid" != "" ]]; then
        kill -9 $api_pid
        sleep 2
    fi
    api_pid=$(ps -ef | grep "$base_dir/antman_api/$antman_api_binary" | grep -v grep | awk '{print $2}')
    if [[ "$api_pid" == "" ]]; then
        antman_log "start antman API service"
        sed -i "/^antmanDir =/cantmanDir = $base_dir" $base_dir/antman_api/conf/app.conf
        if [[ $(cat antman_api/conf/app.conf | grep "httpport = 8001") == "" || $(cat antman_api/conf/app.conf | grep "antmanDir = $base_dir") == "" ]]; then
            antman_log "ANTMAN-004: antman_api conf file $base_dir/antman_api/conf/app.conf is incorrect" "ERROR"
            antman_log "Please modify $base_dir/antman_api/conf/app.conf as follows:\n\nappname = antman_api\nhttpport = 8001\nrunmode = prod\nloglevel = info\n\n[SERVICE]\nantmanDir = $base_dir\n\n"
            exit 1
        fi
        nohup $base_dir/antman_api/$antman_api_binary > /dev/null 2>&1 &
    fi
}

start_antman_api_service

ensure_sshpass

function auto_calc_resource() {
    source $base_dir/obcluster.conf
    cpu_num=`cat /proc/cpuinfo | grep ^processor | wc -l`
    memKB=`grep MemTotal /proc/meminfo | awk '{print $2}'`
    memGB=`expr $memKB / 1024 / 1024`
    total_cpu=`expr $cpu_num - $OCP_DOCKER_CPUS`
    ob_cpu_num=`expr $total_cpu - $OBPROXY_DOCKER_CPUS`
    total_memGB=`expr $memGB - ${OCP_DOCKER_MEMORY%G}`
    ob_memGB=`expr $total_memGB - ${OCP_DOCKER_MEMORY%G}`G
    sed -i "/^OB_DOCKER_CPUS/cOB_DOCKER_CPUS=$ob_cpu_num" $base_dir/obcluster.conf
    sed -i "/^OB_DOCKER_MEMORY/cOB_DOCKER_MEMORY=$ob_memGB" $base_dir/obcluster.conf
}

#auto_calc_resource

function gen_keys() {
    gen_private_key
    sys=`gen_pass`
    meta=`gen_pass`
    monitor=`gen_pass`
    sys_monitor=`gen_pass`
    omsmeta=`gen_pass`
    odcmeta=`gen_pass`
    encode_pass "${sys}" "sys"
    encode_pass "${meta}" "meta"
    encode_pass "${monitor}" "monitor"
    encode_pass "${sys_monitor}" "sys_monitor"
    encode_pass "${omsmeta}" "omsmeta"
    encode_pass "${odcmeta}" "odcmeta"
}
gen_keys

CLUSTER_SYS_PASS=`get_sys_pass`
OCPMETA_TENANT_PASS=`get_meta_pass`


function generate_param_and_check() {
    # check legality of obcluster.conf before installation
    duplicate_param=$(cat $base_dir/obcluster.conf | grep '=' | awk -F'=' '{print $1}' | sort | uniq -c | awk '{if ($1 > 1) print $2}')
    if [[ "$duplicate_param" != "" ]]; then
        antman_log "ANTMAN-003: duplicate param found in $base_dir/obcluster.conf, please check" "ERROR"
        for item in $duplicate_param; do
            cat $base_dir/obcluster.conf | grep -E "^$item="
        done
        exit 1
    fi

    [ -z "$SSH_AUTH" -a -z "$SSH_USER" -a -z "$SSH_PASSWORD" -a -z "$SSH_PORT" -a -z "$SSH_KEY_FILE" ] && antman_log "****** SSH related environment varialbes is not set, will use below default values: ******"
    export SSH_AUTH=${SSH_AUTH:-password} SSH_USER=${SSH_USER:-root} SSH_PORT=${SSH_PORT:-22} SSH_PASSWORD=${SSH_PASSWORD:-} SSH_KEY_FILE=${SSH_KEY_FILE:-/root/.ssh/id_rsa}
    if [ -z "$SSH_PASSWORD" ]; then
        antman_log "SSH_AUTH=${SSH_AUTH} SSH_USER=${SSH_USER} SSH_PORT=${SSH_PORT} SSH_PASSWORD= SSH_KEY_FILE=${SSH_KEY_FILE}"
    else
        antman_log "SSH_AUTH=${SSH_AUTH} SSH_USER=${SSH_USER} SSH_PORT=${SSH_PORT} SSH_PASSWORD=${SSH_PASSWORD:0:2}*** SSH_KEY_FILE=${SSH_KEY_FILE}"
    fi
    [ "$SSH_AUTH" != password -a "$SSH_AUTH" != pubkey ] && { antman_log "env SSH_AUTH invalid, must be password or pubkey" "ERROR"; exit 1; }

    is_ip_legal ZONE1_RS_IP $ZONE1_RS_IP
    if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') != "TRUE" ]]; then
        is_ip_legal ZONE2_RS_IP $ZONE2_RS_IP
        is_ip_legal ZONE3_RS_IP $ZONE3_RS_IP
    fi
    is_docker_cpu_legal OB_DOCKER_CPUS $OB_DOCKER_CPUS
    is_docker_mem_legal OB_DOCKER_MEMORY $OB_DOCKER_MEMORY
    is_docker_cpu_legal OCP_DOCKER_CPUS $OCP_DOCKER_CPUS
    is_docker_mem_legal OCP_DOCKER_MEMORY $OCP_DOCKER_MEMORY
    is_docker_cpu_legal OBPROXY_DOCKER_CPUS $OBPROXY_DOCKER_CPUS
    is_docker_mem_legal OBPROXY_DOCKER_MEMORY $OBPROXY_DOCKER_MEMORY
    is_port_legal MYSQL_PORT $MYSQL_PORT
    is_port_legal RPC_PORT $RPC_PORT
    is_port_legal SSH_PORT $SSH_PORT
    is_port_legal OCP_PORT $OCP_PORT
    is_port_legal OBPROXY_PORT $OBPROXY_PORT
    is_password_legal OCPMETA_TENANT_PASS
    is_password_legal OCPMONITOR_TENANT_PASS
    is_password_legal CLUSTER_SYS_PASS
    is_password_legal OMS_METADB_TENANT_PASS
    is_password_legal ODC_METADB_TENANT_PASS

    # check whether required tools are installed or not
    EXPECT_TOOLS=(mysql curl)
    for tool in ${EXPECT_TOOLS[@]}; do
        $tool --version > /dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            antman_log "ANTMAN-003: $tool is NOT installed, please check" "ERROR"
        fi
    done

    # generate required parameters
    if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') == "TRUE" ]]; then
        LB_MODE="${LB_MODE:-none}"
        ZONE_RS_IP_LIST=($ZONE1_RS_IP)
        DNS_SERVER_IP_LIST=($DNS_MASTER_IP)
        ZONE_NAME_LIST=($ZONE1_NAME)
        ZONE_REGION_LIST=($ZONE1_REGION)
    else
        LB_MODE="${LB_MODE:-dns}"
        ZONE_RS_IP_LIST=($ZONE1_RS_IP $ZONE2_RS_IP $ZONE3_RS_IP)
        DNS_SERVER_IP_LIST=($DNS_MASTER_IP $DNS_SLAVE_IP $DNS_THIRD_IP)
        ZONE_NAME_LIST=($ZONE1_NAME $ZONE2_NAME $ZONE3_NAME)
        ZONE_REGION_LIST=($ZONE1_REGION $ZONE2_REGION $ZONE3_REGION)
    fi
    DNS_SERVER_IP_LIST_STR=$(echo ${DNS_SERVER_IP_LIST[@]} | tr ' ' ',')
    ZONE_RS_IP_LIST_STR=$(echo ${ZONE_RS_IP_LIST[@]} | tr ' ' ',')

    echo LB_MODE=$LB_MODE
    if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') == "TRUE" ]]; then
        sed -i "/^OBPROXY_VIP=/cOBPROXY_VIP=$ZONE1_RS_IP" $base_dir/obcluster.conf
        sed -i "/^OBPROXY_VPORT=/cOBPROXY_VPORT=$OBPROXY_PORT" $base_dir/obcluster.conf
        sed -i "/^OCP_VIP=/cOCP_VIP=$ZONE1_RS_IP" $base_dir/obcluster.conf
        sed -i "/^OCP_VPORT=/cOCP_VPORT=$OCP_PORT" $base_dir/obcluster.conf
    fi
    if [[ "$LB_MODE" == "dns" ]]; then
        is_port_legal NGINX_PORT $NGINX_PORT
        is_port_legal OCP_DNS_VPORT $OCP_DNS_VPORT
        if [[ "$DNS_ZONE_NAME" == "" || "$OCP_DNS_VPORT" == "" ]]; then
            antman_log "ANTMAN-003: LB_MODE=$LB_MODE, but config DNS_ZONE_NAME/OCP_DNS_VPORT is NOT good, please check obcluster.conf" "ERROR"
            exit 1
        fi
        sed -i "/^LB_MODE/cLB_MODE=dns" $base_dir/obcluster.conf

        sed -i "/^OBPROXY_VIP=/cOBPROXY_VIP=$OCP_OBPROXY_DNS_NAME.$DNS_ZONE_NAME" $base_dir/obcluster.conf
        sed -i "/^OBPROXY_VPORT=/cOBPROXY_VPORT=$OBPROXY_PORT" $base_dir/obcluster.conf
        sed -i "/^OCP_VIP=/cOCP_VIP=$OCP_DNS_NAME.$DNS_ZONE_NAME" $base_dir/obcluster.conf
        sed -i "/^OCP_VPORT=/cOCP_VPORT=$OCP_DNS_VPORT" $base_dir/obcluster.conf
    elif [[ "$LB_MODE" == "nlb" ]]; then
        is_port_legal NLB_API_PORT "$NLB_API_PORT"
        is_port_legal NLB_ETCD_PEER_PORT "$NLB_ETCD_PEER_PORT"
        is_port_legal NLB_ETCD_CLIENT_PORT "$NLB_ETCD_CLIENT_PORT"
        is_port_legal OBPROXY_NLB_VPORT "$OBPROXY_NLB_VPORT"
        is_port_legal OCP_NLB_VPORT     "$OCP_NLB_VPORT"
        if [[ "$NLB_VIP_WITH_SUBNET" =~ [0-9]/[0-9]{1,2} ]]; then
            NLB_VIP=${NLB_VIP_WITH_SUBNET%/*}
        else
            antman_log "ANTMAN-003: LB_MODE=$LB_MODE, but config NLB_VIP_WITH_SUBNET is NOT good, please check obcluster.conf" "ERROR"
            exit 1
        fi
        sed -i "/^LB_MODE/cLB_MODE=nlb" "$base_dir"/obcluster.conf
        sed -i "/^OBPROXY_VIP=/cOBPROXY_VIP=$NLB_VIP" "$base_dir"/obcluster.conf
        sed -i "/^OBPROXY_VPORT=/cOBPROXY_VPORT=$OBPROXY_NLB_VPORT" "$base_dir"/obcluster.conf
        sed -i "/^OCP_VIP=/cOCP_VIP=$NLB_VIP" "$base_dir"/obcluster.conf
        sed -i "/^OCP_VPORT=/cOCP_VPORT=$OCP_NLB_VPORT" "$base_dir"/obcluster.conf
        [[ -z "$NLB_IP_LIST" ]] && sed -i "/^NLB_IP_LIST=/cNLB_IP_LIST=$ZONE_RS_IP_LIST_STR" "$base_dir"/obcluster.conf
    elif [[ "$LB_MODE" == "f5" ]]; then
        #is_ip_format_legal $OBPROXY_F5_VIP
        is_port_legal OBPROXY_F5_VPORT $OBPROXY_F5_VPORT
        #is_ip_format_legal $OCP_F5_VIP
        is_port_legal OCP_F5_VPORT $OCP_F5_VPORT
        if [[ "$OBPROXY_F5_VIP" == "" || "$OBPROXY_F5_VPORT" == "" || "$OCP_F5_VIP" == "" || "$OCP_F5_VPORT" == "" ]]; then
            antman_log "ANTMAN-003: LB_MODE=$LB_MODE, but config OBPROXY_F5_VIP/OBPROXY_F5_VPORT/OCP_F5_VIP/OCP_F5_VPORT is NOT good, please check obcluster.conf" "ERROR"
            exit 1
        fi
        sed -i "/^LB_MODE/cLB_MODE=f5" $base_dir/obcluster.conf

        sed -i "/^OBPROXY_VIP=/cOBPROXY_VIP=$OBPROXY_F5_VIP" $base_dir/obcluster.conf
        sed -i "/^OBPROXY_VPORT=/cOBPROXY_VPORT=$OBPROXY_F5_VPORT" $base_dir/obcluster.conf
        sed -i "/^OCP_VIP=/cOCP_VIP=$OCP_F5_VIP" $base_dir/obcluster.conf
        sed -i "/^OCP_VPORT=/cOCP_VPORT=$OCP_F5_VPORT" $base_dir/obcluster.conf
        
    elif [[ "$LB_MODE" == "none" ]]; then
        if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') != "TRUE" ]]; then
            antman_log "ANTMAN-003: LB_MODE=$LB_MODE is unsupported on 3 OCP, please use dns or f5" "ERROR"
            exit 1
        fi
        sed -i "/^LB_MODE/cLB_MODE=none" $base_dir/obcluster.conf
    else
        antman_log "ANTMAN-003: LB_MODE=$LB_MODE is unsupported" "ERROR"
        exit 1
    fi
    source $base_dir/obcluster.conf

    case $INSTALL_STEPS in  # steps is string
        *3* )
            [ -n "$OB_DOCKER_IMAGE_PACKAGE" -a ! -f $base_dir/$OB_DOCKER_IMAGE_PACKAGE ] && { antman_log "specfied ob image $OB_DOCKER_IMAGE_PACKAGE not exist!"; exit 1; }
            ;;&
        *5* | *7* )
            [ -n "$OCP_DOCKER_IMAGE_PACKAGE" -a ! -f $base_dir/$OCP_DOCKER_IMAGE_PACKAGE ] && { antman_log "specfied ocp image $OCP_DOCKER_IMAGE_PACKAGE not exist!"; exit 1; }
            ;;&
        *6* )
            if [[ "$OB_IMAGE_TAG" =~ "OBP" ]]; then
                antman_log "use inner proxy, OBPROXY settings is ignore"
            else
                [ -n "$OBPROXY_DOCKER_IMAGE_PACKAGE" -a ! -f $base_dir/$OBPROXY_DOCKER_IMAGE_PACKAGE ] && { antman_log "specfied obproxy image $OBPROXY_DOCKER_IMAGE_PACKAGE not exist!"; exit 1; }
            fi
            ;;&
        *9* )
            [ -n "$OMS_DOCKER_IMAGE_PACKAGE" -a ! -f $base_dir/$OMS_DOCKER_IMAGE_PACKAGE ] && { antman_log "specfiedoms image $OMS_DOCKER_IMAGE_PACKAGE not exist!"; exit 1; }
            ;;&
        *10* )
            [ -n "$ODC_DOCKER_IMAGE_PACKAGE" -a ! -f $base_dir/$ODC_DOCKER_IMAGE_PACKAGE ] && { antman_log "specfied odc image $ODC_DOCKER_IMAGE_PACKAGE not exist!"; exit 1; }
            ;;&
        *11* )
            [ -n "$OCP_GRAFANA_IMAGE_PACKAGE" -a ! -f $base_dir/$OCP_GRAFANA_IMAGE_PACKAGE ] && { antman_log "specfied ocp grafana image $OCP_GRAFANA_IMAGE_PACKAGE not exist!"; exit 1; }
            ;;&
        *12* )
            [ -n "$OCP_OPENSEARCH_IMAGE_PACKAGE" -a ! -f $base_dir/$OCP_OPENSEARCH_IMAGE_PACKAGE ] && { antman_log "specfied ocp grafana image $OCP_OPENSEARCH_IMAGE_PACKAGE not exist!"; exit 1; }
            ;;&
    esac
}

generate_param_and_check

sh_install_OB_docker="${base_dir}/install_OB_docker.sh"
obcluster_conf="${base_dir}/obcluster.conf"
install_status_log="$LOG_DIR/install_status.log"
uninstall_status_log="$LOG_DIR/uninstall_status.log"

if [ ! -f $install_status_log ]; then
    echo "step | substep | server | status | start_time | end_time" > $install_status_log
fi
if [ ! -f $uninstall_status_log ]; then
    echo "step | substep | server | status | start_time | end_time" > $uninstall_status_log
fi

function ssh_auth() {
    #打通安装机器到目标三台机器的ssh
    /bin/bash $base_dir/ssh_auth/sshtunnel.sh
} > $LOG_DIR/$FUNCNAME.log 2>&1

function ssh_auth_check() {
    local  __error_msg=$1
    local  myresult='SUCCESS'

    for server in ${ZONE_RS_IP_LIST[@]}
    do
        ssh -o ConnectTimeout=5 -o PreferredAuthentications=publickey -p ${SSH_PORT} root@$server 'date'
        if  [[ $? -ne 0 ]]; then
            myresult="ANTMAN-101: ssh to $server failed, check $LOG_DIR/$FUNCNAME.log for detail"
            break;
        fi
    done
    eval $__error_msg="'$myresult'"
} > $LOG_DIR/$FUNCNAME.log 2>&1

function prepare_uninstall_scripts_on_remote() {
    local target_ip=$1
    _ssh "$target_ip" "[ -d ${base_dir}/common ] || mkdir -p ${base_dir}/common"
    _scp "$target_ip" $base_dir/uninstall.sh
    _ssh "$target_ip" "chmod +x $base_dir/uninstall.sh"  # dd write lost x
    _scp "$target_ip" $base_dir/obcluster.conf
    _scp "$target_ip" $base_dir/common/utils.sh
}

function scp_package() {
    local target_ip=$1
    _ssh $target_ip "[ -d ${base_dir}/common ] || mkdir -p ${base_dir}/common"
    [ -n "$OB_DOCKER_IMAGE_PACKAGE" ] && _scp "$target_ip" ${base_dir}/${OB_DOCKER_IMAGE_PACKAGE}
    _scp "$target_ip" $sh_install_OB_docker
    _scp "$target_ip" $obcluster_conf
    _scp "$target_ip" $base_dir/common/utils.sh
    _scp "$target_ip" /root/.key
}

function uninstall_ob_haproxy(){
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "uninstall" "2" "uninstall_ob_haproxy" ${ZONE_RS_IP} "doing"
        prepare_uninstall_scripts_on_remote ${ZONE_RS_IP}
        _ssh ${ZONE_RS_IP} "$base_dir/uninstall.sh haproxy ${DEBUG} ${ZONE_RS_IP}"
        is_docker_removed ${ZONE_RS_IP} "uninstall.sh haproxy " ${ob_haproxy_image_REPO}:${ob_haproxy_image_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "ob_haproxy docker on $ZONE_RS_IP is removed"
            update_status_log "uninstall" "2" "uninstall_ob_haproxy" ${ZONE_RS_IP} "success"
        else
            antman_log "ANTMAN-304: ob_haproxy docker on $ZONE_RS_IP is NOT removed" "ERROR"
            update_status_log "uninstall" "2" "uninstall_ob_haproxy" ${ZONE_RS_IP} "fail"
            exit 1
        fi
    done
}

function install_ob_haproxy() {
    local pids=()
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "install" "2" "install_ob_haproxy" ${ZONE_RS_IP} "doing"
        /bin/bash $base_dir/install_ob_haproxy_remote.sh ${ZONE1_RS_IP} ${SSH_PORT} ${DEBUG} 2>&1 | tee $LOG_DIR/install_ob_haproxy_${ZONE_RS_IP}.log &
        pids+=($!)
        antman_log "installing ob_haproxy on ${ZONE_RS_IP}, pid=$! log: $LOG_DIR/install_ob_haproxy_${ZONE_RS_IP}.log"
    done

    antman_log "waiting on installation of haproxy on all hosts finish"

    for pid in "${pids[@]}"; do
        wait $pid
    done

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        is_error_existed "ERROR" $LOG_DIR/install_ob_haproxy_${ZONE_RS_IP}.log
        local err_ret=$?
        is_docker_running ${ZONE_RS_IP} "install_ob_haproxy.sh" ${ob_haproxy_image_REPO}:${ob_haproxy_image_TAG}
        local docker_ret=$?
        is_haproxy_existed ${ZONE_RS_IP} "install_ob_haproxy.sh"
        local haproxy_ret=$?
        is_keepalived_existed ${ZONE_RS_IP} "install_ob_haproxy.sh"
        local keepalived_ret=$?

        if [[ $err_ret -eq 0 || $docker_ret -ne 0 || $haproxy_ret -ne 0 || $keepalived_ret -ne 0 ]]; then
            antman_log "ANTMAN-305: ob_haproxy docker on $ZONE_RS_IP is NOT started" "ERROR"
            update_status_log "install" "2" "install_ob_haproxy" ${ZONE_RS_IP} "fail"
        else
            antman_log "ob_haproxy docker on $ZONE_RS_IP is started"
            update_status_log "install" "2" "install_ob_haproxy" ${ZONE_RS_IP} "success"
        fi
    done

    is_error_in_logs "$LOG_DIR/install_ob_haproxy" "${ZONE_RS_IP_LIST[*]}" && return 1
    antman_log "ob_haproxy installation on all hosts done"
    return 0
}

function uninstall_ob_dns(){
    # rollback /etc/resolv.conf and  $rc_file
    /bin/bash ${base_dir}/update_dns_resolve_remote.sh "${ZONE_RS_IP_LIST_STR}" ${SSH_PORT} "del" "${DNS_SERVER_IP_LIST_STR}"

    for DNS_SERVER_IP in ${DNS_SERVER_IP_LIST[@]}
    do
        update_status_log "uninstall" "2" "uninstall_ob_dns" ${DNS_SERVER_IP} "doing"
        prepare_uninstall_scripts_on_remote ${DNS_SERVER_IP}
        _ssh ${DNS_SERVER_IP} "$base_dir/uninstall.sh dns ${DEBUG} ${DNS_SERVER_IP}"
        is_docker_removed ${DNS_SERVER_IP} "uninstall.sh dns " ${OB_DNS_IMAGE_REPO}:${OB_DNS_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "ob_dns docker on $DNS_SERVER_IP is removed"
            update_status_log "uninstall" "2" "uninstall_ob_dns" ${DNS_SERVER_IP} "success"
        else
            antman_log "ANTMAN-306: ob_dns docker on $DNS_SERVER_IP is NOT removed" "ERROR"
            update_status_log "uninstall" "2" "uninstall_ob_dns" ${DNS_SERVER_IP} "fail"
            exit 1
        fi
    done
}

function install_ob_dns() {
    local index=1
    for DNS_SERVER_IP in ${DNS_SERVER_IP_LIST[@]}
    do
        update_status_log "install" "2" "install_ob_dns" ${DNS_SERVER_IP} "doing"
        antman_log "installing ob_dns on ${DNS_SERVER_IP}, log: $LOG_DIR/install_ob_dns_${DNS_SERVER_IP}.log"
        /bin/bash $base_dir/install_ob_dns_remote.sh ${DNS_SERVER_IP} ${SSH_PORT} ${DEBUG} 2>&1 | tee $LOG_DIR/install_ob_dns_${DNS_SERVER_IP}.log

        is_error_existed "ERROR" $LOG_DIR/install_ob_dns_${DNS_SERVER_IP}.log
        local err_ret=$?
        is_docker_running ${DNS_SERVER_IP} "install_ob_dns.sh" ${OB_DNS_IMAGE_REPO}:${OB_DNS_IMAGE_TAG}
        local docker_ret=$?

        if [[ $err_ret -eq 0 || $docker_ret -ne 0 ]]; then
            antman_log "ANTMAN-307: ob_dns docker on $DNS_SERVER_IP is NOT started" "ERROR"
            update_status_log "install" "2" "install_ob_dns" ${DNS_SERVER_IP} "fail"
            exit 1
        else
            antman_log "ob_dns docker on $DNS_SERVER_IP is started"
            check_dns_service ${DNS_SERVER_IP} "ns${index}.${DNS_ZONE_NAME}"
            if [[ $? == 0 ]]; then
                update_status_log "install" "2" "install_ob_dns" ${DNS_SERVER_IP} "success"
            else
                update_status_log "install" "2" "install_ob_dns" ${DNS_SERVER_IP} "fail"
                exit 1
            fi
        fi
        ((index++))
    done
    antman_log "ob_dns installation on all hosts done"
    # update /etc/resolv.conf and $rc_file
    /bin/bash ${base_dir}/update_dns_resolve_remote.sh "${ZONE_RS_IP_LIST_STR}" ${SSH_PORT} "add" "${DNS_SERVER_IP_LIST_STR}"
}

function uninstall_ob(){
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "uninstall" "3" "uninstall_ob" ${ZONE_RS_IP} "doing"
        prepare_uninstall_scripts_on_remote ${ZONE_RS_IP}
        _ssh ${ZONE_RS_IP} "$base_dir/uninstall.sh ob ${DEBUG} ${ZONE_RS_IP}"
        is_docker_removed ${ZONE_RS_IP} "uninstall.sh ob " ${OB_IMAGE_REPO}:${OB_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "OB docker on $ZONE_RS_IP is removed"
            update_status_log "uninstall" "3" "uninstall_ob" ${ZONE_RS_IP} "success"
        else
            antman_log "ANTMAN-307: OB docker on $ZONE_RS_IP is NOT removed" "ERROR"
            update_status_log "uninstall" "3" "uninstall_ob" ${ZONE_RS_IP} "fail"
            exit 1
        fi
    done
}

function major_freeze(){
    last_merged_version=$(mysql -h$ZONE1_RS_IP -P$MYSQL_PORT -uroot@sys -Doceanbase -e "select value from __all_zone where name='last_merged_version' and zone='';" | grep -v value)
    mysql -h$ZONE1_RS_IP -P$MYSQL_PORT -uroot@sys -Doceanbase -e "alter system major freeze;"
    for i in {1..60}
    do
        sleep 30
        curr_merged_version=$(mysql -h$ZONE1_RS_IP -P$MYSQL_PORT -uroot@sys -Doceanbase -e "select value from __all_zone where name='last_merged_version' and zone='';" | grep -v value)
        if [[ $curr_merged_version -gt $last_merged_version ]]; then
            echo "pass"
            break
        elif [[ $i -eq 20 ]]; then
            echo "warn"
        elif [[ $i -eq 60 ]]; then
            echo "fail"
        fi
    done
}

function install_ob() {
    update_status_log "install" "3" "scp_package_ob" ${ZONE1_RS_IP} "doing"
    local pids=()
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        scp_package $ZONE_RS_IP &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait $pid
    done
    update_status_log "install" "3" "scp_package_ob" ${ZONE1_RS_IP} "success"

    ROOTSERVICE_LIST=""
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        if [[ "$ROOTSERVICE_LIST" == "" ]]; then
            ROOTSERVICE_LIST="$ZONE_RS_IP:$RPC_PORT:$MYSQL_PORT"
        else
            ROOTSERVICE_LIST="$ROOTSERVICE_LIST;$ZONE_RS_IP:$RPC_PORT:$MYSQL_PORT"
        fi
    done

    local index=0
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        ZONE_NAME=${ZONE_NAME_LIST[$index]}
        update_status_log "install" "3" "install_ob" ${ZONE_RS_IP} "doing"
        _ssh $ZONE_RS_IP "cd ${base_dir};chmod +x $sh_install_OB_docker;[ -d $LOG_DIR ] || mkdir -p $LOG_DIR; RANDOM_PROXY_PASSWORD=$RANDOM_PROXY_PASSWORD nohup $sh_install_OB_docker $ZONE_NAME $ZONE_RS_IP \"$ROOTSERVICE_LIST\" ${DEBUG} 2>&1 | tee $LOG_DIR/install_OB_docker.log &"
        antman_log "installing OB docker and starting OB server on $ZONE_RS_IP, pid: $!, log: $LOG_DIR/install_OB_docker.log and /home/admin/logs/ob-server/ inside docker"
        ((index++))
    done

    local total_waittime=0
    local wait_unit=3
    local max_waittime=60

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        is_docker_running ${ZONE_RS_IP} "install_OB_docker.sh" ${OB_IMAGE_REPO}:${OB_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -ne 0 ]] ; then
            antman_log "ANTMAN-303: OB docker on $ZONE_RS_IP is NOT started" "ERROR"
            update_status_log "install" "3" "install_ob" ${ZONE_RS_IP} "fail"
            return 1
        fi
    done

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        antman_log "waiting on observer ready on $ZONE_RS_IP"
        while true; do
            res=$(mysql -h$ZONE_RS_IP -P$MYSQL_PORT -uroot -e "" 2>&1)
            if [[ $? -eq 0 ]] ; then
                antman_log "observer on $ZONE_RS_IP is ready"
                update_status_log "install" "3" "install_ob" ${ZONE_RS_IP} "success"
                break
            fi
            if [[ total_waittime -gt $max_waittime ]] ; then
                antman_log "ANTMAN-301: waiting on observer ready on $ZONE_RS_IP timeout($max_waittime Minitues)" "ERROR"
                antman_log "Last error info: $res" "ERROR"
                update_status_log "install" "3" "install_ob" ${ZONE_RS_IP} "fail"
                return 1
            fi
            [ $total_waittime -ge $wait_unit ] && let "wait_unit=1"
            let "total_waittime=total_waittime + wait_unit"
            sleep $((wait_unit*60))
            antman_log "waiting on observer ready on $ZONE_RS_IP for $total_waittime Minitues"
        done
    done
    antman_log "observer installation on all hosts done"

    local index=0
    update_status_log "install" "3" "bootstrap_ob" ${ZONE1_RS_IP} "doing"
    local bootstrap_sql=""
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        ZONE_NAME=${ZONE_NAME_LIST[$index]}
        ZONE_REGION=${ZONE_REGION_LIST[$index]}
        if [[ "$bootstrap_sql" == "" ]]; then
            bootstrap_sql="alter system bootstrap REGION \"$ZONE_REGION\" ZONE \"$ZONE_NAME\" SERVER \"$ZONE_RS_IP:$RPC_PORT\""
        else
            bootstrap_sql="$bootstrap_sql, REGION \"$ZONE_REGION\" ZONE \"$ZONE_NAME\" SERVER \"$ZONE_RS_IP:$RPC_PORT\""
        fi
        ((index++))
    done
    antman_log "Now, start bootstrap on $ZONE1_RS_IP: $bootstrap_sql"
    mysql -h$ZONE1_RS_IP -P$MYSQL_PORT -uroot -e "set ob_query_timeout=1000000000; $bootstrap_sql;"
    if [[ $? -ne 0 ]]; then
        antman_log "ANTMAN-302: execute alter system bootstrap FAILED!" "ERROR"
        update_status_log "install" "3" "bootstrap_ob" ${ZONE1_RS_IP} "fail"
        return 1
    fi
    wait_unit=1
    total_waittime=0
    max_waittime=10
    while true; do
        sleep 60
        let "total_waittime=total_waittime+1"

        res=$(mysql -h$ZONE1_RS_IP -P$MYSQL_PORT -uroot -Doceanbase -e "" 2>&1)
        if [[ $? -eq 0 ]] ; then
            antman_log "bootstrap done, observer now ready"
            update_status_log "install" "3" "bootstrap_ob" ${ZONE1_RS_IP} "success"
            break
        fi
        if [[ total_waittime -gt $max_waittime ]] ; then
            antman_log "ANTMAN-302: failed to bootstrap observer, timeout($max_waittime Minitues)" "ERROR"
            antman_log "Last error info: $res" "ERROR"
            update_status_log "install" "3" "bootstrap_ob" ${ZONE1_RS_IP} "fail"
            return 1
        fi
        antman_log "waiting bootstrap for $total_waittime Minitues"
    done

    antman_log "major_freeze start"
    major_freeze_res=$(major_freeze)
    if [[ $major_freeze_res == "warn" ]]; then
        antman_log "ANTMAN-219: major freeze time exceed 10 minutes, please check the cluster performance!" "WARN"
    elif [[ $major_freeze_res == "fail" ]]; then
        antman_log "ANTMAN-219: major freeze time exceed 30 minutes, TIMEOUT!" "ERROR"
    else
        antman_log "major_freeze done"
    fi
}

function init_metadb() {
    update_status_log "install" "4" "init_metadb" ${ZONE1_RS_IP} "doing"
    /bin/bash $base_dir/create_ocp_db.sh
} > $LOG_DIR/$FUNCNAME.log 2>&1

function uninit_metadb()
{
    update_status_log "uninstall" "4" "uninit_metadb" ${ZONE1_RS_IP} "doing"
    set -x
    mysql -uroot@ocp_meta -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${OCPMETA_TENANT_PASS} -e "drop database if exists ocp"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop user ocp_monitor"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists S4_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists S3_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists S2_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists S1_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists S0_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists LogOnlySystem_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists LogOnlyNormal_unit_config"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists B_unit_config"
    ob_version=$(mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -N -e "select version()")
    if [[ "$ob_version" == "2."* ]]; then
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists ocp_monitor force"
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists ocp_meta force"
    else
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists ocp_monitor"
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists ocp_meta"
    fi
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource pool if exists ocp_monitor_pool"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource pool if exists ocp_resource_pool"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists ocp_monitor_unit"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists ocp_unit"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "SET PASSWORD FOR 'root' = PASSWORD('')"
    [[ $DEBUG == "FALSE" ]] && set +x
    update_status_log "uninstall" "4" "uninit_metadb" ${ZONE1_RS_IP} "success"
} > $LOG_DIR/$FUNCNAME.log 2>&1

function install_tmp_ocp() {
    update_status_log "install" "5" "install_tmp_ocp" ${ZONE1_RS_IP} "doing"
    /bin/bash $base_dir/install_ocp_remote.sh ${ZONE1_RS_IP} ${SSH_PORT} ${ZONE1_RS_IP} ${MYSQL_PORT} ${OCP_METADB_USERNAME} "ocp1" ${DEBUG} TRUE

    is_error_existed "ERROR" $LOG_DIR/install_tmp_ocp.log
    local err_ret=$?
    is_docker_running ${ZONE1_RS_IP} "install_ocp.sh" ${OCP_IMAGE_REPO}:${OCP_IMAGE_TAG}
    local docker_ret=$?

    if [[ $err_ret -eq 0 || $docker_ret -ne 0 ]]; then
        antman_log "ANTMAN-308: install tmp_ocp error or tmp_ocp docker on $ZONE1_RS_IP is NOT started" "ERROR"
        update_status_log "install" "5" "install_tmp_ocp" ${ZONE1_RS_IP} "fail"
        return 1
    else
        antman_log "tmp_ocp docker on $ZONE1_RS_IP is started"
        update_status_log "install" "5" "install_tmp_ocp" ${ZONE1_RS_IP} "success"
    fi
}

function clear_init_tables() {
    OCPMETA_TENANT_PASS=`get_meta_pass`
    OCPMONITOR_TENANT_PASS=`get_monitor_pass`
    mysql -uroot@ocp_meta -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${OCPMETA_TENANT_PASS} -e "drop database if exists ocp; create database if not EXISTS ocp"
    mysql -uroot@ocp_monitor -h${ZONE1_RS_IP} -P$MYSQL_PORT -p${OCPMONITOR_TENANT_PASS} -e "drop database if exists ocp_monitor; create database if not EXISTS ocp_monitor"
}

function uninstall_tmp_ocp(){
    update_status_log "uninstall" "5" "uninstall_tmp_ocp" ${ZONE1_RS_IP} "doing"
    prepare_uninstall_scripts_on_remote ${ZONE1_RS_IP}
    _ssh ${ZONE1_RS_IP} "$base_dir/uninstall.sh ocp ${DEBUG} ${ZONE1_RS_IP}"
    is_docker_removed ${ZONE1_RS_IP} "uninstall.sh ocp " ${OCP_IMAGE_REPO}:${OCP_IMAGE_TAG}
    local docker_ret=$?
    if [[ $docker_ret -eq 0 ]]; then
        antman_log "tmp_ocp docker on $ZONE1_RS_IP is removed"
        update_status_log "uninstall" "5" "uninstall_tmp_ocp" ${ZONE1_RS_IP} "success"
    else
        antman_log "ANTMAN-309: tmp_ocp docker on $ZONE1_RS_IP is NOT removed" "ERROR"
        update_status_log "uninstall" "5" "uninstall_tmp_ocp" ${ZONE1_RS_IP} "fail"
        return 1
    fi
    echo ${OCP_VERSION} | grep -Eq "^2.[4-9]|^3"
    if [[ $? -eq 0 ]]; then
        clear_init_tables
    fi
}

function update_meta_config() {
    mysql -h${ZONE1_RS_IP} -P${OBPROXY_PORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OCP_MONITORDB_USERNAME}#${obcluster_name}' where \`key\` = 'ocp.monitordb.username';"
    mysql -h${ZONE1_RS_IP} -P${OBPROXY_PORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OBPROXY_VIP}' where \`key\` = 'ocp.monitordb.host';"
    mysql -h${ZONE1_RS_IP} -P${OBPROXY_PORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OBPROXY_VPORT}' where \`key\` = 'ocp.monitordb.port';"
    mysql -h${ZONE1_RS_IP} -P${OBPROXY_PORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OCPMONITOR_TENANT_PASS}' where \`key\` = ' ocp.monitordb.password';"
    mysql -h${ZONE1_RS_IP} -P${OBPROXY_PORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OCP_MONITOR_DBNAME}' where \`key\` = 'ocp.monitordb.database';"
    mysql -h${ZONE1_RS_IP} -P${OBPROXY_PORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='http://${OCP_VIP}:${OCP_VPORT}' where \`key\` = 'ocp.site.url';"
    # 使用自带proxy管理，不要修改
    # mysql -h${OBPROXY_VIP} -P${OBPROXY_VPORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OBPROXY_VIP}' where \`key\` = 'ocp.system.obproxy.address';"
    # mysql -h${OBPROXY_VIP} -P${OBPROXY_VPORT} -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update config_properties set value='${OBPROXY_VPORT}' where \`key\` = 'ocp.system.obproxy.port';"
}

function install_obproxy() {
    update_status_log "install" "6" "wait_obproxy_ready" ${ZONE1_RS_IP} "doing"

    local pids=()
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "install" "6" "install_obproxy" ${ZONE_RS_IP} "doing"
        /bin/bash $base_dir/install_obproxy_remote.sh ${ZONE_RS_IP} ${SSH_PORT} ${DEBUG} 2>&1 | tee $LOG_DIR/install_obproxy_${ZONE_RS_IP}.log  &
        pids+=($!)
        antman_log "installing obproxy on ${ZONE_RS_IP}, pid=$! log: $LOG_DIR/install_obproxy_${ZONE_RS_IP}.log"
    done

    for pid in "${pids[@]}"; do
        wait $pid
    done

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        is_error_existed "ERROR" $LOG_DIR/install_obproxy_${ZONE_RS_IP}.log
        local err_ret=$?
        is_docker_running ${ZONE_RS_IP} "install_obproxy.sh" ${OBPROXY_IMAGE_REPO}:${OBPROXY_IMAGE_TAG}
        local docker_ret=$?

        if [[ $err_ret -eq 0 || $docker_ret -ne 0 ]]; then
            antman_log "ANTMAN-309: obproxy docker on $ZONE_RS_IP is NOT started" "ERROR"
            update_status_log "install" "6" "install_obproxy" ${ZONE_RS_IP} "fail"
            return 1
        else
            antman_log "obproxy docker on $ZONE_RS_IP is started"
            update_status_log "install" "6" "install_obproxy" ${ZONE_RS_IP} "success"
        fi
    done

    is_error_in_logs "$LOG_DIR/install_obproxy" "${ZONE_RS_IP_LIST[*]}" && return 1
    antman_log "obproxy installation on all hosts done"
}

function uninstall_obproxy(){
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "uninstall" "6" "uninstall_obproxy" ${ZONE_RS_IP} "doing"
        prepare_uninstall_scripts_on_remote ${ZONE_RS_IP}
        _ssh ${ZONE_RS_IP} "$base_dir/uninstall.sh obproxy ${DEBUG} ${ZONE_RS_IP}"
        is_docker_removed ${ZONE_RS_IP} "uninstall.sh obproxy " ${OBPROXY_IMAGE_REPO}:${OBPROXY_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "obproxy docker on $ZONE_RS_IP is removed"
            update_status_log "uninstall" "6" "uninstall_obproxy" ${ZONE_RS_IP} "success"
        else
            antman_log "ANTMAN-310: obproxy docker on $ZONE_RS_IP is NOT removed" "ERROR"
            update_status_log "uninstall" "6" "uninstall_obproxy" ${ZONE_RS_IP} "fail"
            return 1
        fi
    done
}


function install_ocp() {
    need_init=$1  # TRUE or FALSE
    if [ "$need_init" = "TRUE" ]; then
        antman_log "start ocp1 and init it..."
    else
        antman_log "restart ocp1 using proxy, already inited..."
    fi
    /bin/bash $base_dir/install_ocp_remote.sh ${ZONE_RS_IP_LIST[0]} ${SSH_PORT} ${OBPROXY_VIP} ${OBPROXY_VPORT} "${OCP_METADB_USERNAME}#${obcluster_name}" "ocp1" ${DEBUG} ${need_init} 2>&1 | tee $LOG_DIR/install_ocp_${ZONE_RS_IP_LIST[0]}.log
    _ssh $ZONE1_RS_IP "docker ps --format '{{.ID}}\t{{.Names}}' | grep -q -w ${OCP_CONTAINER_NAME}" \
    || { antman_log "ocp1 install failed" "ERROR"; return 1; }
    # mc config
    if [ "$OCP_MC_ENABLED" = "TRUE" ]; then
        _ssh $ZONE1_RS_IP "docker exec -w /home/admin/ocp-init/src/ocp-init $OCP_CONTAINER_NAME python modify_mc_config.py --multicluster_mode_enabled=true --cluster_id=$OCP_MC_ID --cluster_name=$OCP_MC_NAME --cluster_role=$OCP_MC_ROLE" \
        || { antman_log "config multi cluster on $ZONE1_RS_IP failed, please check!" "ERROR"; return 1; }
    else
        antman_log "OCP multi cluster disabled, pass."
    fi
    # update ocp parameters
    if echo ${OCP_VERSION} | grep -Eq "^2.[4-9]|^3"; then
        update_meta_config
    fi
    _ssh $ZONE1_RS_IP "docker restart $OCP_CONTAINER_NAME" || { antman_log "restart ocp on $ZONE1_RS_IP failed, please check!" "ERROR"; return 1; }
    local pids=()
    local index=2
    for ZONE_RS_IP in "${ZONE_RS_IP_LIST[@]:1:100}"
    do
        update_status_log "install" "7" "install_ocp" ${ZONE_RS_IP} "doing"
        /bin/bash $base_dir/install_ocp_remote.sh ${ZONE_RS_IP} ${SSH_PORT} ${OBPROXY_VIP} ${OBPROXY_VPORT} "${OCP_METADB_USERNAME}#${obcluster_name}" "ocp${index}" ${DEBUG} 2>&1 | tee $LOG_DIR/install_ocp_${ZONE_RS_IP}.log &
        pids+=($!)
        antman_log "installing ocp on ${ZONE_RS_IP}, pid=$! log: $LOG_DIR/install_ocp_${ZONE_RS_IP}.log"
        ((index++))
        sleep 5
    done

    for pid in "${pids[@]}"; do
        wait $pid
    done

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]:1:100}
    do
        is_error_existed "ERROR" $LOG_DIR/install_ocp_${ZONE_RS_IP}.log
        local err_ret=$?
        is_docker_running ${ZONE_RS_IP} "install_ocp.sh" ${OCP_IMAGE_REPO}:${OCP_IMAGE_TAG}
        local docker_ret=$?

        if [[ $err_ret -eq 0 || $docker_ret -ne 0 ]]; then
            antman_log "ANTMAN-311: ocp docker on $ZONE_RS_IP is NOT started" "ERROR"
            update_status_log "install" "7" "install_ocp" ${ZONE_RS_IP} "fail"
            return 1
        else
            antman_log "ocp docker on $ZONE_RS_IP is started"
            update_status_log "install" "7" "install_ocp" ${ZONE_RS_IP} "success"
        fi
    done
    # waiting ocp port ready, single ocp is restarted
    antman_log "make sure ocp service ready..."
    total_wait_seconds=0
    while true;
    do
        if curl -s --connect-timeout 5 "$ZONE_RS_IP":"$OCP_PORT" &> /dev/null; then
            antman_log "ocp on $ZONE_RS_IP:$OCP_PORT service ready"
            break
        fi
        if [ "$total_wait_seconds" -gt 300 ]; then
            antman_log "ANTMAN-312: ocp on $ZONE_RS_IP:$OCP_PORT can not be visited in 5mins" "ERROR"
            return 1
        fi
        sleep 10
        ((total_wait_seconds+=10))
    done
    is_error_in_logs "$LOG_DIR/install_ocp" "${ZONE_RS_IP_LIST[*]}" && return 1
    antman_log "ocp installation on all hosts done"
    return 0
}

function uninstall_ocp(){
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "uninstall" "7" "uninstall_ocp" ${ZONE_RS_IP} "doing"
        prepare_uninstall_scripts_on_remote ${ZONE_RS_IP}
        _ssh ${ZONE_RS_IP} "$base_dir/uninstall.sh ocp ${DEBUG} ${ZONE_RS_IP}"
        is_docker_removed ${ZONE_RS_IP} "uninstall.sh ocp " ${OCP_IMAGE_REPO}:${OCP_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "ocp docker on $ZONE_RS_IP is removed"
            update_status_log "uninstall" "7" "uninstall_ocp" ${ZONE_RS_IP} "success"
        else
            antman_log "ANTMAN-312: ocp docker on $ZONE_RS_IP is NOT removed" "ERROR"
            update_status_log "uninstall" "7" "uninstall_ocp" ${ZONE_RS_IP} "fail"
            return 1
        fi
    done
}

function install_oms() {

    pids=()
    update_status_log "install" "9" "install_oms" "${OMS_IP_LIST}" "doing"
    for oms_ip in ${OMS_IP_ARRAY[@]};
    do
        /bin/bash $base_dir/install_oms_remote.sh ${oms_ip} ${SSH_PORT} ${DEBUG} 2>&1 | tee $LOG_DIR/install_oms_${oms_ip}.log &
        pids+=($!)
        antman_log "installing oms on ${oms_ip}, pid=$! log: $LOG_DIR/install_oms_${oms_ip}.log"
    done
    wait ${pids[@]}

    for oms_ip in ${OMS_IP_ARRAY[@]};
    do
        is_error_existed "\] ERROR \[" $LOG_DIR/install_oms_${oms_ip}.log  # oms 211日志带supervisor的ERROR
        local err_ret=$?
        if [ $err_ret = 0 ]; then
            antman_log "ANTMAN-311: error occurs in $LOG_DIR/install_oms_${oms_ip}.log" "ERROR"
            update_status_log "install" "9" "install_oms" ${oms_ip} "fail"
            return 1
        fi
        is_docker_running ${oms_ip} "install_oms.sh" ${OMS_IMAGE_REPO}:${OMS_IMAGE_TAG}
        local docker_ret=$?

        if [[ $docker_ret -ne 0 ]]; then
            antman_log "ANTMAN-311: oms docker on $oms_ip is NOT started" "ERROR"
            update_status_log "install" "9" "install_oms" ${oms_ip} "fail"
            return 1
        else
            antman_log "oms docker on $oms_ip is started"
            update_status_log "install" "9" "install_oms" ${oms_ip} "success"
        fi
    done
    antman_log "oms installation on all hosts done"
    return 0
}

function uninstall_oms() {
    update_status_log "uninstall" "9" "uninstall_oms" ${OMS_IP_LIST} "doing"
    ob_version=$(mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -N -e "select version()")
    if [[ "$ob_version"* == "2."* ]]; then
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists $OMS_METADB_TENANT force"
    else
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists $OMS_METADB_TENANT"
    fi
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource pool if exists oms_resource_pool"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists oms_unit"

    for oms_ip in ${OMS_IP_ARRAY[@]};
    do
        prepare_uninstall_scripts_on_remote ${oms_ip}
        _ssh ${oms_ip} "$base_dir/uninstall.sh oms ${DEBUG} ${oms_ip}" || return 1
        is_docker_removed ${oms_ip} "uninstall.sh oms " ${OMS_IMAGE_REPO}:${OMS_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "oms docker on $oms_ip is removed"
            update_status_log "uninstall" "9" "uninstall_oms" ${oms_ip} "success"
        else
            antman_log "ANTMAN-312: oms docker on $oms_ip is NOT removed" "ERROR"
            update_status_log "uninstall" "9" "uninstall_oms" ${oms_ip} "fail"
            return 1
        fi
    done
}

function create_odc_meta_tenant() {
    ZONE_LIST=""
    for ZONE_NAME in ${ZONE_NAME_LIST[@]}
    do
        if [[ "$ZONE_LIST" == "" ]]; then
            ZONE_LIST="'$ZONE_NAME'"
        else
            ZONE_LIST="$ZONE_LIST,'$ZONE_NAME'"
        fi
    done

    #create odc meta tenant
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p$CLUSTER_SYS_PASS -e "CREATE RESOURCE UNIT IF NOT EXISTS odc_unit max_cpu 1, max_memory '5G', max_iops 128,max_disk_size '1G', max_session_num 10000, MIN_CPU=1, MIN_MEMORY= '5G', MIN_IOPS=128;"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p$CLUSTER_SYS_PASS -e "CREATE RESOURCE POOL IF NOT EXISTS odc_resource_pool  unit='odc_unit', unit_num=1, zone_list=($ZONE_LIST);"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p$CLUSTER_SYS_PASS -e "CREATE TENANT IF NOT EXISTS ${ODC_METADB_TENANT} charset='utf8mb4', zone_list=($ZONE_LIST), primary_zone='$ZONE1_NAME', resource_pool_list=('odc_resource_pool');"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p$CLUSTER_SYS_PASS -e "ALTER TENANT ${ODC_METADB_TENANT} SET VARIABLES ob_tcp_invited_nodes='%';"

    ODC_METADB_TENANT_PASS=`get_odcmeta_pass`
    
    #设置租户密码
    mysql -uroot@${ODC_METADB_TENANT} -h${ZONE1_RS_IP} -P$MYSQL_PORT -e "SET PASSWORD FOR 'root' = PASSWORD('${ODC_METADB_TENANT_PASS}')"

    #set meta parameters and variables
    mysql -uroot@${ODC_METADB_TENANT} -h${ZONE1_RS_IP} -P$MYSQL_PORT -p${ODC_METADB_TENANT_PASS} -e "SET global recyclebin = 'OFF';"
    mysql -uroot@${ODC_METADB_TENANT} -h${ZONE1_RS_IP} -P$MYSQL_PORT -p${ODC_METADB_TENANT_PASS} -e "SET global ob_create_table_strict_mode=false;"

    #create odc metadb
    mysql -uroot@${ODC_METADB_TENANT} -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${ODC_METADB_TENANT_PASS} -e "create database if not EXISTS $ODC_METADB_DBNAME"

    mysql -uroot@${ODC_METADB_TENANT} -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${ODC_METADB_TENANT_PASS} -D$ODC_METADB_DBNAME -e "source meta_sql/odc/odc_meta.sql"

    gt_230=$(echo ${ODC_IMAGE_TAG} | python -c "import re; v=raw_input(); print re.match(r'\d\.\d\.\d', v) and v >= '2.3.0' ")
    [ ${gt_230} = 'True' ] && return   # 230以上自动创建表结构
    
    gt_210=$(echo ${ODC_IMAGE_TAG} | python -c "import re; v=raw_input(); print re.match(r'\d\.\d\.\d', v) and v >= '2.1.0' ")
    gt_220=$(echo ${ODC_IMAGE_TAG} | python -c "import re; v=raw_input(); print re.match(r'\d\.\d\.\d', v) and v >= '2.2.0' ")
    gt_221=$(echo ${ODC_IMAGE_TAG} | python -c "import re; v=raw_input(); print re.match(r'\d\.\d\.\d', v) and v >= '2.2.1' ")
    [ ${gt_210} = 'True' ] && mysql -uroot@${ODC_METADB_TENANT} -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${ODC_METADB_TENANT_PASS} -D$ODC_METADB_DBNAME -e "source meta_sql/odc/odc_meta_210.sql"
    [ ${gt_220} = 'True' ] && mysql -uroot@${ODC_METADB_TENANT} -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${ODC_METADB_TENANT_PASS} -D$ODC_METADB_DBNAME -e "source meta_sql/odc/odc_meta_220.sql"
    [ ${gt_221} = 'True' ] && mysql -uroot@${ODC_METADB_TENANT} -P$MYSQL_PORT -h${ZONE1_RS_IP} -p${ODC_METADB_TENANT_PASS} -D$ODC_METADB_DBNAME -e "source meta_sql/odc/odc_meta_221.sql"

}

function install_odc() {
    create_odc_meta_tenant 2>&1 | tee $LOG_DIR/create_odc_meta_tenant.log 2>&1
    grep -i error $LOG_DIR/create_odc_meta_tenant.log && return 1 

    local pids=()
    local index=1
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "install" "10" "install_odc" ${ZONE_RS_IP} "doing"
        /bin/bash $base_dir/install_odc_remote.sh ${ZONE_RS_IP} ${SSH_PORT} ${DEBUG} 2>&1 | tee $LOG_DIR/install_odc_${ZONE_RS_IP}.log &
        pids+=($!)
        antman_log "installing odc on ${ZONE_RS_IP}, pid=$! log: $LOG_DIR/install_odc_${ZONE_RS_IP}.log"
    done

    for pid in "${pids[@]}"; do
        wait $pid
    done

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        is_error_existed "ERROR" $LOG_DIR/install_odc_${ZONE_RS_IP}.log
        local err_ret=$?
        is_docker_running ${ZONE_RS_IP} "install_odc.sh" ${ODC_IMAGE_REPO}:${ODC_IMAGE_TAG}
        local docker_ret=$?

        if [[ $err_ret -eq 0 || $docker_ret -ne 0 ]]; then
            antman_log "ANTMAN-311: odc docker on $ZONE_RS_IP is NOT started" "ERROR"
            update_status_log "install" "10" "install_odc" ${ZONE_RS_IP} "fail"
            return 1
        else
            antman_log "odc docker on $ZONE_RS_IP is started"
            update_status_log "install" "10" "install_odc" ${ZONE_RS_IP} "success"
        fi
    done

    is_error_in_logs "$LOG_DIR/install_odc" "${ZONE_RS_IP_LIST[*]}" && return 1
    antman_log "odc installation on all hosts done"
    return 0
}

function uninstall_odc() {
    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        update_status_log "uninstall" "10" "uninstall_odc" ${ZONE_RS_IP} "doing"
        prepare_uninstall_scripts_on_remote ${ZONE_RS_IP}
        _ssh ${ZONE_RS_IP} "$base_dir/uninstall.sh odc ${DEBUG} ${ZONE_RS_IP}"
        is_docker_removed ${ZONE_RS_IP} "uninstall.sh odc " ${ODC_IMAGE_REPO}:${ODC_IMAGE_TAG}
        local docker_ret=$?
        if [[ $docker_ret -eq 0 ]]; then
            antman_log "odc docker on $ZONE_RS_IP is removed"
            update_status_log "uninstall" "10" "uninstall_odc" ${ZONE_RS_IP} "success"
        else
            antman_log "ANTMAN-312: odc docker on $ZONE_RS_IP is NOT removed" "ERROR"
            update_status_log "uninstall" "10" "uninstall_odc" ${ZONE_RS_IP} "fail"
            return 1
        fi
    done
    ob_version=$(mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -N -e "select version()")
    if [[ "$ob_version"* == "2."* ]]; then
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists $ODC_METADB_TENANT force"
    else
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop TENANT if exists $ODC_METADB_TENANT"
    fi
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource pool if exists odc_resource_pool"
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -e "drop resource unit if exists odc_unit"

}

function validate_network() {
    # use --pre for env with haproxy and keepalived, use --pre-vip-ready for env with vip ready
    /bin/bash $base_dir/validate_service.sh --pre
}

function check_lb_connection() {
    for i in {1..30}
    do
        antman_log "check_lb_connection: $i time"
        /bin/bash $base_dir/validate_service.sh --pre-vip-ready
        if [[ $? -eq 0 ]]; then
            return 0
        fi
        sleep 10
    done
    antman_log "ANTMAN-315: check_lb_connection FAILED! Max retry times(30) exceeded" "ERROR"
    return 1
}

function post_check_service() {
    /bin/bash $base_dir/validate_service.sh --post
}

function insert_status_log() {
    local step=$2
    local substep=$3
    local server_list=$4
    local status=$5
    local pos=""
    if [[ $1 == "install" ]]; then
        local status_log=$install_status_log
        for i in $(cat $status_log | awk '{print $1}' | grep -P "\d")
        do
            if [[ $i -gt $step ]]; then
                pos=$i
                break
            fi
        done
    elif [[ $1 == "uninstall" ]]; then
        local status_log=$uninstall_status_log
        for i in $(cat $status_log | awk '{print $1}' | grep -P "\d")
        do
            if [[ $i -lt $step ]]; then
                pos=$i
                break
            fi
        done
    else
        antman_log "INVALID action! current action: $1" "ERROR"
        exit 1
    fi

    for server in $(echo $server_list | awk -F ',' '{for(i=1;i<=NF;i++){print $i}}')
    do
        local record=$(cat $status_log | grep -P "^$step\t$substep\t$server\t")
        if [[ "$record" != "" ]]; then
            sed -i "/^$step\t$substep\t$server/c$step\t$substep\t$server\t$status" $status_log
        elif [[ "$pos" != "" ]]; then
            record=$(cat $status_log | grep -P "^$pos" | head -1)
            sed -i "/^$record$/i$step\t$substep\t$server\t$status" $status_log
        else
            echo -e "$step\t$substep\t$server\t$status" >> $status_log
        fi
    done
}

function update_status_log() {
    if [[ $1 == "install" ]]; then
        local status_log=$install_status_log
    elif [[ $1 == "uninstall" ]]; then
        local status_log=$uninstall_status_log
    else
        antman_log "INVALID action! current action: $1" "ERROR"
        exit 1
    fi
    local step=$2
    local substep=$3
    local server=$4
    local status=$5
    if [[ $status == "doing" ]]; then
        start_time=$(date +"%Y-%m-%d %T")
        sed -i "/^$step\t$substep\t$server/c$step\t$substep\t$server\t$status\t$start_time" $status_log
    elif [[ $status == "success" || $status == "fail" ]]; then
        start_time=$(cat $status_log | grep -P "^$step\t$substep\t$server\t" | awk '{print $5" "$6}')
        if [[ $start_time == " " ]]; then
            start_time=$(date +"%Y-%m-%d %T")
        fi
        end_time=$(date +"%Y-%m-%d %T")
        sed -i "/^$step\t$substep\t$server/c$step\t$substep\t$server\t$status\t$start_time\t$end_time" $status_log
    fi
}

function is_obagent_existed() {
    is_proc_existed $1 $2 "obstat|ob_" 8
    return $?
}

function is_haproxy_existed() {
    is_proc_existed $1 $2 "haproxy" 1
    return $?
}

function is_keepalived_existed() {
    is_proc_existed $1 $2 "keepalived" 1
    return $?
}

function check_dns_service() {
    for i in {1..12}
    do
        nsRes=`dig @$1 $2 +short`
        if [[ ${nsRes} == $1 ]]; then
            antman_log "ob_dns service on $1 is ready"
            return 0
        fi
        sleep 5
    done
    antman_log "ANTMAN-307: ob_dns service on $1 is NOT working" "ERROR"
    return 1
}

# function step0()
# {
#     #pre_check
# }

function clear_step1()
{
    antman_log "$FUNCNAME: no need to clear for step ssh authorization"
}

function step1()
{
    antman_log "$FUNCNAME: check ssh authorization, logfile: $LOG_DIR/ssh_auth.log"
    update_status_log "install" "1" "ssh_auth" ${ZONE1_RS_IP} "doing"
    for ip in "${ZONE_RS_IP_LIST[@]}"
    do
        if [ "$(_ssh "$ip" "id -un")" != root ]; then
            [[ "$SSH_USER" = root ]] && prompt='' || prompt=" Make sure $SSH_USER can execute [sudo bash] without password and /etc/sudoers has no requiretty setting"
            antman_log "$FUNCNAME: ssh authorization to $ip failed, Please check SSH affinity environment varialbes and execute \"install.sh -h\" for more details.${prompt}" "ERROR"
            antman_log "For example:" "ERROR"
            antman_log "\"export SSH_PASSWORD=123456; sh install.sh -i 1-8\" will connect remote server with user \"root\" and password \"123123\"" "ERROR"
            antman_log "\"export SSH_AUTH=pubkey; sh install.sh -i 1-8\" will connect remote server with user \"root\" and pravate key  \"/root/.ssh/id_rsa\"" "ERROR"
            update_status_log "install" "1" "ssh_auth" ${ZONE1_RS_IP} "fail"
            exit 1
        fi
    done
    antman_log "$FUNCNAME: ssh authorization done"
    update_status_log "install" "1" "ssh_auth" ${ZONE1_RS_IP} "success"
}

function clear_step2()
{
    if [[ "$LB_MODE" == "dns" ]]; then
        antman_log "$FUNCNAME: cleaning ob_dns, logfile: $LOG_DIR/uninstall_ob_dns.log"
        uninstall_ob_dns 2>&1 | tee $LOG_DIR/uninstall_ob_dns.log
        if [ ${PIPESTATUS[0]} -ne 0 ] ; then
            antman_log "ANTMAN-314: ERROR occurred in uninstall_ob_dns, install.sh exit" "ERROR"
            #grep "ERROR" $LOG_DIR/uninstall_ob_dns.log
            exit 1
        fi
        antman_log "$FUNCNAME: uninstallation of ob dns done"
    elif [[ "$LB_MODE" == "haproxy" ]]; then
        antman_log "$FUNCNAME: cleaning haproxy, logfile: $LOG_DIR/uninstall_ob_haproxy.log"
        uninstall_ob_haproxy 2>&1 | tee $LOG_DIR/uninstall_ob_haproxy.log
        if [ ${PIPESTATUS[0]} -ne 0 ] ; then
            antman_log "ANTMAN-314: ERROR occurred in uninstall_ob_haproxy, install.sh exit" "ERROR"
            #grep "ERROR" $LOG_DIR/uninstall_ob_haproxy.log
            exit 1
        fi
        antman_log "$FUNCNAME: uninstallation of ob haproxy done"
    elif [[ $LB_MODE = "nlb" ]]; then
        IFS="," read -r -a ip_array <<<"$NLB_IP_LIST"
        antman_log "${FUNCNAME[*]}: cleaning nlb on ${ip_array[*]}"
        for ip in "${ip_array[@]}";
        do
            is_ip_legal "NLB ip" "$ip"
            local container_id
            container_id=$(_ssh "$ip" "docker ps -a --format '{{.ID}}\t{{.Image}}' | grep -w $NLB_IMAGE_REPO:$NLB_IMAGE_TAG | awk '{print \$1}'")
            if [ -n "$container_id" ]; then
                _ssh  "$ip" "docker stop $container_id && docker rm $container_id && rm -rf $NLB_DATA_DIR/etcd_data" && antman_log "delete nlb on $ip success." || { antman_log "delet nlb on $ip failed" "ERROR"; exit 1; }
            else
                antman_log "nlb is already deleted on $ip"
            fi
        done
    antman_log "cleanup nlb success."
    fi
}

function step2_dns()
{
    for DNS_SERVER_IP in "${DNS_SERVER_IP_LIST[@]}"
    do
        antman_log "$FUNCNAME: check whether NGINX port $OCP_DNS_VPORT,$NGINX_PORT is in use or not on $DNS_SERVER_IP"
        check_port_in_use $DNS_SERVER_IP $OCP_DNS_VPORT
        check_port_in_use $DNS_SERVER_IP $NGINX_PORT
        antman_log "$FUNCNAME: NGINX port $OCP_DNS_VPORT,$NGINX_PORT is idle on $DNS_SERVER_IP"
    done

    antman_log "$FUNCNAME: installing ob_dns, logfile: $LOG_DIR/install_ob_dns.log"
    install_ob_dns 2>&1 | tee $LOG_DIR/install_ob_dns.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_ob_dns, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_ob_dns.log
        exit 1
    fi

    if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') != "TRUE" ]]; then
        antman_log "$FUNCNAME: checking lb connection, logfile: $LOG_DIR/check_lb_connection.log"
        update_status_log "install" "2" "check_lb_connection" ${ZONE1_RS_IP} "doing"
        check_lb_connection 2>&1 | tee $LOG_DIR/check_lb_connection.log
        if [ ${PIPESTATUS[0]} -ne 0 ] ; then
            antman_log "ANTMAN-314: ERROR occurred in check_lb_connection, install.sh exit" "ERROR"
            #grep "ERROR" $LOG_DIR/check_lb_connection.log
            update_status_log "install" "2" "check_lb_connection" ${ZONE1_RS_IP} "fail"
            exit 1
        fi
        update_status_log "install" "2" "check_lb_connection" ${ZONE1_RS_IP} "success"
    fi

    antman_log "$FUNCNAME: installation of ob_dns done"
}

function step2_haproxy()
{
    antman_log "$FUNCNAME: validating network, logfile: $LOG_DIR/validate_network.log"
    update_status_log "install" "2" "validate_network" ${ZONE1_RS_IP} "doing"
    validate_network 2>&1 | tee $LOG_DIR/validate_network.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in validate_network, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/validate_network.log
        update_status_log "install" "2" "validate_network" ${ZONE1_RS_IP} "fail"
        exit 1
    fi
    update_status_log "install" "2" "validate_network" ${ZONE1_RS_IP} "success"

    antman_log "$FUNCNAME: installing haproxy, logfile: $LOG_DIR/install_ob_haproxy.log"
    install_ob_haproxy 2>&1 | tee $LOG_DIR/install_ob_haproxy.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_ob_haproxy, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_ob_haproxy_*.log
        exit 1
    fi
    sed -i "/^LB_MODE/cLB_MODE=haproxy" $base_dir/obcluster.conf
    antman_log "$FUNCNAME: checking lb connection, logfile: $LOG_DIR/check_lb_connection.log"
    update_status_log "install" "2" "check_lb_connection" ${ZONE1_RS_IP} "doing"
    check_lb_connection 2>&1 | tee $LOG_DIR/check_lb_connection.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in check_lb_connection, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/check_lb_connection.log
        update_status_log "install" "2" "check_lb_connection" ${ZONE1_RS_IP} "fail"
        exit 1
    fi
    update_status_log "install" "2" "check_lb_connection" ${ZONE1_RS_IP} "success"

    antman_log "$FUNCNAME: installation of haproxy done"
}

function step2_nlb()
{
    IFS="," read -r -a ip_array <<<"$NLB_IP_LIST"
    antman_log "$FUNCNAME: installing nlb on ${ip_array[*]}"
    for ip in "${ip_array[@]}";
    do
        is_ip_legal "NLB ip" "$ip"
        is_port_legal NLB_API_PORT "$NLB_API_PORT"
        check_port_in_use "$ip" "$NLB_API_PORT"
        if [[ -z "$NLB_IMAGE_PACKAGE" ]]; then
            antman_log "NLB_IMAGE_PACKAGE is empty, skip docker load"
        else
            if _ssh "$ip" "docker load" < "$base_dir/$NLB_IMAGE_PACKAGE"; then
                antman_log "docker load on $ip success"
            else
                antman_log "docker load on $ip failed" "ERROR"
                exit 1
            fi
        fi
    done
    antman_log "start nlb container..."
    local cmd res
    cmd="docker run -d --net host --name nlb --cap-add=NET_ADMIN -v $NLB_DATA_DIR:/usr/local/apisix/logs \
-e VIP_WITH_NETMASK=$NLB_VIP_WITH_SUBNET -e IP_LIST=$NLB_IP_LIST -e API_PORT=$NLB_API_PORT -e API_PASSWORD=$NLB_API_PASSWORD  \
-e KEEPALIVED_ROUTER_ID=$NLB_KEEPALIVED_ROUTER_ID -e NLB_ETCD_PEER_PORT=$NLB_ETCD_PEER_PORT -e NLB_ETCD_CLIENT_PORT=$NLB_ETCD_CLIENT_PORT \
$NLB_IMAGE_REPO:$NLB_IMAGE_TAG"
    antman_log "start command is: $cmd"
    for ip in "${ip_array[@]}";
    do
        if _ssh "$ip" "$cmd"; then
            antman_log "start container success on $ip"
        else
            antman_log "start container on $ip failed!" "ERROR"
            exit 1
        fi
    done
    sleep 5
    antman_log "test nlb api access..."
    cmd="curl -s -o /dev/null  -w %{http_code} -u root:$NLB_API_PASSWORD $NLB_VIP:$NLB_API_PORT/rule"
    antman_log "check command is $cmd"
    for i in {1..30};
    do
        [ $i -eq 30 ] && { antman_log "nlb api waiting timeout, please check nlb logs for detail" "ERROR"; exit 1; }
        if [[ $($cmd) = 200 ]]; then
            antman_log "nlb api is ready"
            break
        else
            sleep 2
        fi
    done
    antman_log "add OCP and MetaProxy rules..."
    local body backend
    for ip in "${ZONE_RS_IP_LIST[@]}";
    do
        backend="$backend{\"host\":\"$ip\",\"port\":$OCP_PORT, \"weight\":1},"
    done
    backend=${backend%,}

    body=$(cat << eof
{
    "protocal": "http",
    "vip": "$NLB_VIP",
    "vport": $OCP_NLB_VPORT,
    "upstream": {
        "nodes": [$backend],
        "type": "chash"
    }
}
eof
)   
    cmd="curl -s -u 'root:$NLB_API_PASSWORD' $NLB_VIP:$NLB_API_PORT/rule -d'$body'"
    res=$(eval "$cmd")
    antman_log "add OCP rule, command is: $cmd, result is $res"
    if echo $res | grep -q success; then
        antman_log "add OCP rule success"
    else
        antman_log "Add NLB rule of OCP failed!" "ERROR"
        exit 1
    fi

    backend=
    for ip in "${ZONE_RS_IP_LIST[@]}";
    do
        backend="$backend{\"host\":\"$ip\",\"port\":$OBPROXY_PORT,\"weight\":1},"
    done
    backend=${backend%,}
    body=$(cat << eof
{
    "protocal": "tcp",
    "vip": "$NLB_VIP",
    "vport": $OBPROXY_NLB_VPORT,
    "upstream": {
        "nodes": [$backend],
        "type": "roundrobin"
    }
}
eof
) 
    cmd="curl -s -u 'root:$NLB_API_PASSWORD' $NLB_VIP:$NLB_API_PORT/rule -d'$body'"
    res=$(eval "$cmd")
    antman_log "add MetaProxy rule, command is: $cmd, result is $res"
    if echo $res | grep success; then
        antman_log "add MetaProxy rule success"
    else
        antman_log "Add NLB rule of MetaProxy failed!" "ERROR"
        exit 1
    fi
    antman_log "$FUNCNAME: installation of nlb done"
}

function step2() {
    if [[ "$LB_MODE" == "dns" ]]; then
        step2_dns
    elif [[ $LB_MODE = "nlb" ]]; then
        step2_nlb
    else
        antman_log "$FUNCNAME: no action is required when LB_MODE=$LB_MODE"
    fi
}

function clear_step3()
{
    antman_log "$FUNCNAME: uninstalling OB server and remove docker, logfile: $LOG_DIR/uninstall_ob.log"
    uninstall_ob 2>&1 | tee $LOG_DIR/uninstall_ob.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in uninstall_ob, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/uninstall_ob.log
        exit 1
    fi
    antman_log "$FUNCNAME: uninstallation of ob done"
}

function step3()
{
    # system_memory is 50G default
    [ -z "$OB_SYSTEM_MEMORY" ] && OB_SYSTEM_MEMORY=50G
    avail_tenant_memory_num=$((${OB_DOCKER_MEMORY%G} - ${OB_SYSTEM_MEMORY%G}))
    [ $avail_tenant_memory_num -lt 37 ] && { antman_log "docker ob avail tenant memory is (${OB_DOCKER_MEMORY%G} - ${OB_SYSTEM_MEMORY%G})G, docker memory limit(${OB_DOCKER_MEMORY}) too small." "ERROR"; exit 1; }

    # auto generate proxysys and proxyro pass
    OCP_VERSION=$(get_ocp_version)
    echo "OCP_VERSION is $OCP_VERSION"
    if [[ "$OB_IMAGE_TAG" =~ "OBP" ]] && [[ "$OCP_VERSION" > 3.2.0 ]]; then
        gen_private_key
        proxysys_pass=$(gen_pass) # if already exist will not update
        proxyro_pass=$(gen_pass)
        encode_pass "$proxysys_pass" "proxysys"
        encode_pass "$proxyro_pass" "proxyro"
        RANDOM_PROXY_PASSWORD=TRUE
    else
        RANDOM_PROXY_PASSWORD=FALSE
    fi

    for ZONE_RS_IP in "${ZONE_RS_IP_LIST[@]}"
    do
        antman_log "$FUNCNAME: check whether OBSERVER port $MYSQL_PORT,$RPC_PORT are in use or not on $ZONE_RS_IP"
        check_port_in_use $ZONE_RS_IP $MYSQL_PORT
        check_port_in_use $ZONE_RS_IP $RPC_PORT
        check_port_in_use $ZONE_RS_IP 2022  # docker inside ssh port
        [[ "$OB_IMAGE_TAG" =~ "OBP" ]] && check_port_in_use $ZONE_RS_IP $OBPROXY_PORT  # check_proxy port
        antman_log "$FUNCNAME: OBSERVER port $MYSQL_PORT,$RPC_PORT, 2022 are idle on $ZONE_RS_IP"
    done

    antman_log "$FUNCNAME: installing ob cluster, logfile: $LOG_DIR/install_ob.log"
    install_ob 2>&1 | tee $LOG_DIR/install_ob.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_ob, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_ob.log
        exit 1
    fi
    if [[ "$RANDOM_PROXY_PASSWORD" = TRUE ]]; then
        antman_log "create proxyro using random password"
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -N -e "CREATE USER proxyro IDENTIFIED BY '$(decode_pass proxyro)';"
    else
        antman_log "create proxyro using legacy password"
        mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -N -e "CREATE USER proxyro IDENTIFIED BY password '*e9c2bcdc178a99b7b08dd25db58ded2ee5bff050';"
    fi
    mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -N -e "grant select on oceanbase.* to proxyro;"
    [ $? -ne 0 ] && { antman_log "create obproxyro user failed!" "ERROR"; exit 1; }
    antman_log "$FUNCNAME: installation of ob cluster done"
}

function clear_step4()
{
    antman_log "$FUNCNAME: drop ocp meta db/tenant/user/resource, logfile: $LOG_DIR/uninit_metadb.log"
    uninit_metadb
    if [ $? -ne 0 ] ; then
        grep "ERROR" $LOG_DIR/uninit_metadb.log
        exit 1
    fi
    antman_log "$FUNCNAME: uninit of metadb done"
}

function step4()
{
    antman_log "$FUNCNAME: initializing ocp metadb, logfile: $LOG_DIR/init_metadb.log"
    init_metadb
    grep -i error $LOG_DIR/init_metadb.log && update_status_log "install" "4" "init_metadb" ${ZONE1_RS_IP} "fail" && exit 1
    update_status_log "install" "4" "init_metadb" ${ZONE1_RS_IP} "success"
    antman_log "$FUNCNAME: initialization of ocp metadb done"
}

function clear_step5()
{
    [[ "$OB_IMAGE_TAG" =~ "OBP" ]] && { antman_log "using inner Proxy with OB!"; return; }
    antman_log "$FUNCNAME: uninstalling ocp and remove docker, logfile: $LOG_DIR/uninstall_tmp_ocp.log"
    uninstall_tmp_ocp 2>&1 | tee $LOG_DIR/uninstall_tmp_ocp.log 2>&1
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in uninstall_tmp_ocp, install.sh exit" "ERROR"
        exit 1
    fi
    antman_log "$FUNCNAME: uninstallation of temporary ocp done"
}


function get_ocp_version() {
    OCPRPM=`docker run --rm --net host --entrypoint rpm $OCP_IMAGE_REPO:$OCP_IMAGE_TAG -qa | grep ocp-server`
    if [[ $? -eq 0 ]]; then
        OCP_VERSION=`echo ${OCPRPM} | awk -F'-' '{print $3}'`
    else
        OCP_VERSION=2.3.5
    fi
    echo $OCP_VERSION
}

function step5()
{
    OCP_VERSION=`get_ocp_version`
    sed -i "/^OCP_VERSION/cOCP_VERSION=$OCP_VERSION" $base_dir/obcluster.conf
    [[ "$OB_IMAGE_TAG" =~ "OBP" ]] && { antman_log "using inner Proxy with OB!"; return; }
    antman_log "$FUNCNAME: check whether OCP port $OCP_PORT is in use or not on $ZONE1_RS_IP"
    check_port_in_use $ZONE1_RS_IP $OCP_PORT
    antman_log "$FUNCNAME: OCP port $OCP_PORT is idle on $ZONE1_RS_IP"

    antman_log "$FUNCNAME: installing temporary ocp, logfile: $LOG_DIR/install_tmp_ocp.log"
    
    
    if [ -n "$OCP_DOCKER_IMAGE_PACKAGE" ]; then
        antman_log "load docker image: docker load -i $OCP_DOCKER_IMAGE_PACKAGE"
        docker images $OCP_IMAGE_REPO:$OCP_IMAGE_TAG | grep $OCP_IMAGE_TAG
        if [ $? -ne 0 ]; then
            docker load -i $OCP_DOCKER_IMAGE_PACKAGE
        fi 
    else
        antman_log "OCP_DOCKER_IMAGE_PACKAGE is empty, skip docker load."
    fi

    install_tmp_ocp 2>&1 | tee $LOG_DIR/install_tmp_ocp.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_tmp_ocp, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_tmp_ocp.log
        exit 1
    fi

    echo ${OCP_VERSION} | grep -Eq "^2.[4-9]|^3"
    if [[ $? -ne 0 ]]; then
        # remove zone2 and zone3 in single ocp mode
        if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') == "TRUE" ]]; then
            # delete ZONE2 and ZONE3
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "delete from ocp_host where cluster_id like '%ZONE2%';delete from ocp_host where cluster_id like '%ZONE3%';"
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "delete from ocp_resource where dns_ip like '%ZONE2_RS_IP%';delete from ocp_resource where dns_ip like '%ZONE3_RS_IP%';"
            obcluster_config=$(mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -N -e "select rootserver from ocp_instance where obregion_name = '$obcluster_name'")
            new_obcluster_config=$(python -c "import json; json_dict=json.loads('$obcluster_config'); json_dict['RsList'] = [json_dict['RsList'][0]]; print json.dumps(json_dict, separators=(',', ':'))")
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_instance set rootserver='$new_obcluster_config' where obregion_name = '$obcluster_name'"
        fi

        # update ob_version if meta ob is ob2.x
        ob_version=$(mysql -uroot -P$MYSQL_PORT -h${ZONE1_RS_IP} -Doceanbase -p${CLUSTER_SYS_PASS} -N -e "select version()")
        if [[ "$ob_version" == "2."* ]]; then
            ob_version=$(echo $ob_version | awk -F'.' '{print $1"."$2}')
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_instance set ob_version = '$ob_version' where obregion_name = '$obcluster_name';"
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_logic_region set ob_version = '$ob_version' where obregion_name = '$obcluster_name';"
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_user_instance_group set ob_version = '$ob_version' where obregion_group_name = '$obcluster_name';"
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_user_instance set ob_version = '$ob_version' where logic_region_name = '$obcluster_name';"
            mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_resource_group set ob_version = '$ob_version' where name = '$obcluster_name';"
        fi

        # remove ocp_meta and ocp_monitor from ocp_user_instance_group to avoid operation risk
        ocp_metadb_instance_name=$(echo $OCP_METADB_USERNAME | awk -F'@' '{print $2}')
        ocp_monitordb_instance_name=$(echo $OCP_MONITORDB_USERNAME | awk -F'@' '{print $2}')
        mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "DELETE FROM ocp_user_instance_group WHERE user_instance_name IN ('$ocp_metadb_instance_name', '$ocp_monitordb_instance_name') AND obregion_group_name = '$obcluster_name';"
    fi
    
    antman_log "$FUNCNAME: installation of temporary ocp done"
}

function clear_step6()
{
    [[ "$OB_IMAGE_TAG" =~ "OBP" ]] && { antman_log "using inner Proxy with OB!"; return; }
    antman_log "$FUNCNAME: uninstalling obproxy and remove docker, logfile: $LOG_DIR/uninstall_obproxy.log"
    uninstall_obproxy 2>&1 | tee $LOG_DIR/uninstall_obproxy.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in uninstall_obproxy, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/uninstall_obproxy.log
        exit 1
    fi
    antman_log "$FUNCNAME: uninstallation of obproxy done"
}

function step6()
{
    [[ "$OB_IMAGE_TAG" =~ "OBP" ]] && { antman_log "using inner Proxy with OB!"; return; }
    for ZONE_RS_IP in "${ZONE_RS_IP_LIST[@]}"
    do
        antman_log "$FUNCNAME: check whether OBPROXY port $OBPROXY_PORT is in use or not on $ZONE_RS_IP"
        check_port_in_use $ZONE_RS_IP $OBPROXY_PORT
        antman_log "$FUNCNAME: OBPROXY port $OBPROXY_PORT is idle on $ZONE_RS_IP"
    done

    antman_log "$FUNCNAME: installing obproxy, logfile: $LOG_DIR/install_obproxy.log"
    install_obproxy 2>&1 | tee $LOG_DIR/install_obproxy.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_obproxy, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_obproxy.log
        exit 1
    fi
    antman_log "$FUNCNAME: installation of obproxy done"
}

function clear_step7()
{
    antman_log "$FUNCNAME: uninstalling ocp and remove docker, logfile: $LOG_DIR/uninstall_ocp.log"
    uninstall_ocp 2>&1 | tee $LOG_DIR/uninstall_ocp.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in uninstall_ocp, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/uninstall_ocp.log
        exit 1
    fi
    antman_log "$FUNCNAME: uninstallation of ocp done"
}

function ocp_maz_config() {
    [ "$OCP_MAZ_ENABLED" != "TRUE" ] && { antman_log "OCP multi AZ disabled, pass."; return 0; }
    # reset az info, or retry step7 will failed
    _ssh $ZONE1_RS_IP "docker exec -w /home/admin/ocp-init/src/ocp-init $OCP_CONTAINER_NAME python modify_maz_config.py --reset --disable"

    # restart obproxy and ocp
    for ((i=0; i<${#ZONE_RS_IP_LIST[@]}; i++))
    do
        local host_ip=${ZONE_RS_IP_LIST[i]} az_name=${OCP_MAZ_AZ_NAME_LIST[i]} ocp_az_vip=${OCP_MAZ_OCP_VIP_LIST[i]} ocp_az_vport=${OCP_MAZ_OCP_VPORT_LIST[i]} metaproxy_az_vip=${OCP_MAZ_METAPROXY_VIP_LIST[i]} metaproxy_az_vport=${OCP_MAZ_METAPROXY_VPORT_LIST[i]}
        if [ "$OBPROXY_USE_RS" = "TRUE" ]; then
            antman_log "use local rs, skip config metaproxy az configurl"
        elif [[ "$OB_IMAGE_TAG" =~ "OBP" ]]; then
            antman_log "use inner proxy, skip config metaproxy az configurl"
        else
            # execute query to make sure local rs cache generated
            mysql -h$host_ip -P$OBPROXY_PORT -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "select * from compute_host limit 1;" > /dev/null
            _ssh $host_ip "test -e /home/admin/obproxy/etc/obproxy_rslist_info.json" || { antman_log "metaproxy on $host_ip has no rs_info cache, please check!" "ERROR"; exit 1; }
            _ssh $host_ip "docker rm -f $OBPROXY_CONTAINER_NAME && rm -f /home/admin/obproxy/etc/obproxy_config.bin" || { antman_log "metaproxy on $host_ip replace failed, please check!" "ERROR"; exit 1; }

            local az_config_url="http://${ocp_az_vip}:${ocp_az_vport}/services?Action=GetObProxyConfig&User_ID=admin&UID=alibaba"
            _ssh $host_ip "docker run -d --name $OBPROXY_CONTAINER_NAME --net=host \
--cpu-period 100000 \
--cpu-quota $OBPROXY_DOCKER_CPUS"00000" \
--memory=$OBPROXY_DOCKER_MEMORY \
-e OBPROXY_PORT=$OBPROXY_PORT \
-e APPNAME=$OBPROXY_APP_NAME_ARG \
-e OBPROXY_CONFIG_SERVER_URL=\"$az_config_url\" \
-e OPTSTR=\"enable_strict_kernel_release=false,enable_metadb_used=false,enable_proxy_scramble=true,log_dir_size_threshold=10G,automatic_match_work_thread=false,work_thread_num=16,proxy_mem_limited=4G,client_max_connections=16384,enable_compression_protocol=false\" \
-v /home/admin/obproxy/etc:/home/admin/obproxy/etc \
-v /home/admin/obproxy/log:/home/admin/obproxy/log \
--restart on-failure:5 \
$OBPROXY_IMAGE_REPO:$OBPROXY_IMAGE_TAG"
        fi

        for ((j=0; j<=30; j++))
        do
            sleep 2
            mysql -h$host_ip -P$OBPROXY_PORT -u${OCP_METADB_USERNAME}#${obcluster_name} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "select 1;" &>/dev/null && break
            [ $j -eq 30 ] && { antman_log "metaproxy on $host_ip replace success but can not connect in 1 min, please check!" "ERROR"; exit 1; }
        done

        #  config az and restart ocp
        local ocp_env_file=${base_dir}/config/env_ocp.yaml

        _ssh $host_ip "docker exec -w /home/admin/ocp-init/src/ocp-init $OCP_CONTAINER_NAME python modify_maz_config.py --enable --config-az ${az_name} --site-url http://${ocp_az_vip}:${ocp_az_vport} --monitordb.host ${metaproxy_az_vip} --monitordb.port ${metaproxy_az_vport}" || \
        { antman_log "execute modify_maz_config.py --enable --config-az ${az_name} --site-url http://${ocp_az_vip}:${ocp_az_vport} --monitordb.host ${metaproxy_az_vip} --monitordb.port ${metaproxy_az_vport} on $host_ip failed, please check!" "ERROR"; exit 1; }
        _ssh $host_ip "echo 'OCP_CURRENT_AZONE_NAME=${az_name}' >> ${ocp_env_file} && sed -i -e '/^OCP_METADB_HOST=/cOCP_METADB_HOST=${metaproxy_az_vip}' -e '/^OCP_METADB_PORT=/cOCP_METADB_PORT=${metaproxy_az_vport}' ${ocp_env_file} && docker rm -f ${OCP_CONTAINER_NAME}" || \
        { antman_log "alter ocp_env_file and delete non-maz-ocp container on ${host_ip} failed, please check!" "ERROR"; exit 1; }

        if [ $BACKUP_ENABLE = "TRUE" ]; then
            cmd="docker run -d --name $OCP_CONTAINER_NAME --net=host --cpu-period 100000 --cpu-quota $OCP_DOCKER_CPUS"00000" --memory=$OCP_DOCKER_MEMORY --env-file=$ocp_env_file -v $PHYSICAL_BACKUP_DIR:/obbackup -v /home/admin/logs:/home/admin/logs --restart on-failure:5 $OCP_IMAGE_REPO:$OCP_IMAGE_TAG"
        else
            cmd="docker run -d --name $OCP_CONTAINER_NAME --net=host --cpu-period 100000 --cpu-quota $OCP_DOCKER_CPUS"00000" --memory=$OCP_DOCKER_MEMORY --env-file=$ocp_env_file -v /home/admin/logs:/home/admin/logs --restart on-failure:5 $OCP_IMAGE_REPO:$OCP_IMAGE_TAG"
        fi
        antman_log "start ocp with az on $host_ip: $cmd"
        _ssh "$host_ip" "$cmd"
    done
    antman_log "sleep 120s to wait all ocp restart ..."
    sleep 120
}

function step7()
{
    for ZONE_RS_IP in "${ZONE_RS_IP_LIST[@]}"
    do
        if [[ $ZONE_RS_IP == $ZONE1_RS_IP ]]; then
            continue
        fi
        antman_log "$FUNCNAME: check whether OCP port $OCP_PORT is in use or not on $ZONE_RS_IP"
        check_port_in_use $ZONE_RS_IP $OCP_PORT
        antman_log "$FUNCNAME: OCP port $OCP_PORT is idle on $ZONE_RS_IP"
    done

    antman_log "$FUNCNAME: installing ocp, logfile: $LOG_DIR/install_ocp.log"
    if [[ "$OB_IMAGE_TAG" =~ "OBP" ]]; then
        antman_log "using inner Proxy with OB!"
        install_ocp TRUE 2>&1 | tee $LOG_DIR/install_ocp.log
    else
        antman_log "legacy install ocp"
        install_ocp FALSE 2>&1 | tee $LOG_DIR/install_ocp.log
    fi
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_ocp, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_ocp.log
        exit 1
    fi

    # fix stale task
    mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_api_task set status = 'success', finish_time = now() where id in (1,2,3);"
    mysql -h${ZONE1_RS_IP} -P${MYSQL_PORT} -u${OCP_METADB_USERNAME} -D${OCP_METADB_DBNAME} -p${OCPMETA_TENANT_PASS} -e "update ocp_inner_task set status = 'success' where api_task_id in (1,2,3);"

    ocp_maz_config
    antman_log "$FUNCNAME: installation of ocp done"
}

function clear_step8()
{
    antman_log "$FUNCNAME: no need to clear for step network post-check"
}

function step8()
{
    antman_log "$FUNCNAME: post-checking service, logfile: $LOG_DIR/post_check_service.log"
    update_status_log "install" "8" "post_check_service" ${ZONE1_RS_IP} "doing"
    post_check_service 2>&1 | tee $LOG_DIR/post_check_service.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in post_check_service, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/post_check_service.log
        update_status_log "install" "8" "post_check_service" ${ZONE1_RS_IP} "fail"
        exit 1
    fi
    update_status_log "install" "8" "post_check_service" ${ZONE1_RS_IP} "success"
    antman_log "$FUNCNAME: post check done"
    ##need add other post check
}

function clear_step9()
{
    [[ -z $OMS_IP_LIST ]] && { antman_log "OMS_IP_LIST is empty!" "ERROR"; exit 1; }
    OMS_IP_ARRAY=($(echo $OMS_IP_LIST | sed 's/,/ /g'))
    antman_log "$FUNCNAME: uninstalling oms and remove docker, logfile: $LOG_DIR/uninstall_oms.log"
    uninstall_oms 2>&1 | tee $LOG_DIR/uninstall_oms.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in uninstall_oms, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/uninstall_oms.log
        exit 1
    fi
    antman_log "$FUNCNAME: uninstallation of oms done"
}

function step9()
{
    is_docker_cpu_legal OMS_DOCKER_CPUS $OMS_DOCKER_CPUS
    is_docker_mem_legal OMS_DOCKER_MEMORY $OMS_DOCKER_MEMORY

    [[ -z $OMS_IP_LIST ]] && { antman_log "OMS_IP_LIST is empty!" "ERROR"; exit 1; }
    OMS_IP_ARRAY=($(echo $OMS_IP_LIST | sed 's/,/ /g'))

    for oms_ip in ${OMS_IP_ARRAY[@]};
    do
        is_ip_legal OMS_IP $oms_ip
        if [ "$(_ssh "$oms_ip" "id -un")" != root ]; then
            [[ "$SSH_USER" = root ]] && prompt='' || prompt=" Make sure $SSH_USER can execute [sudo bash] without password and /etc/sudoers has no requiretty setting"
            antman_log "$FUNCNAME: ssh authorization to $ip failed, Please check SSH affinity environment varialbes.${prompt}" "ERROR"
            exit 1
        fi
        for p in {9000,9001,9999,8084,8086,8087,8088,8089};
        do
            antman_log "$FUNCNAME: check whether OMS port $p is in use or not on $oms_ip"
            is_port_legal OMS_PORT $p
            check_port_in_use $oms_ip $p
            antman_log "$FUNCNAME: OMS port $p is idle on $oms_ip"
        done
        [[ "$LB_MODE" == "dns" ]] && /bin/bash ${base_dir}/update_dns_resolve_remote.sh ${oms_ip} ${SSH_PORT} "add" "${DNS_SERVER_IP_LIST_STR}"
    done
    
    antman_log "$FUNCNAME: installing oms, logfile: $LOG_DIR/install_oms.log"
    install_oms 2>&1 | tee $LOG_DIR/install_oms.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_oms, install.sh exit" "ERROR"
        exit 1
    fi
    antman_log "$FUNCNAME: installation of oms done"
}

function clear_step10()
{
    antman_log "$FUNCNAME: uninstalling odc and remove docker, logfile: $LOG_DIR/uninstall_odc.log"
    uninstall_odc 2>&1 | tee $LOG_DIR/uninstall_odc.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in uninstall_odc, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/uninstall_odc.log
        exit 1
    fi
    antman_log "$FUNCNAME: uninstallation of odc done"
}

function step10()
{
    is_port_legal ODC_PORT $ODC_PORT
    is_docker_cpu_legal ODC_DOCKER_CPUS $ODC_DOCKER_CPUS
    is_docker_mem_legal ODC_DOCKER_MEMORY $ODC_DOCKER_MEMORY

    for ZONE_RS_IP in ${ZONE_RS_IP_LIST[@]}
    do
        antman_log "$FUNCNAME: check whether ODC port $ODC_PORT is in use or not on $ZONE_RS_IP"
        check_port_in_use $ZONE_RS_IP $ODC_PORT
        antman_log "$FUNCNAME: ODC port $ODC_PORT is idle on $ZONE_RS_IP"
    done

    antman_log "$FUNCNAME: installing odc, logfile: $LOG_DIR/install_odc.log"
    install_odc 2>&1 | tee $LOG_DIR/install_odc.log
    if [ ${PIPESTATUS[0]} -ne 0 ] ; then
        antman_log "ANTMAN-314: ERROR occurred in install_odc, install.sh exit" "ERROR"
        #grep "ERROR" $LOG_DIR/install_odc.log
        exit 1
    fi
    antman_log "$FUNCNAME: installation of odc done"
}


function step11(){
    antman_log "start install ocp grafana on $OCP_GRAFANA_IP..."
    [ $(echo ${OCP_VERSION} | python -c "import re; v=raw_input(); print bool(re.match(r'\d\.\d\.\d', v)) ") = "False" ] && { antman_log "unknown ocp version: $OCP_VERSION" "ERROR"; exit 1; }
    local gt_320=$(echo ${OCP_VERSION} | python -c "import re; v=raw_input(); print re.match(r'\d\.\d\.\d', v) and v >= '3.2.0' ")
    local user_pass
    if [ "$gt_320" = True ]; then
        user_pass=admin:aaAA11__
    else
        user_pass=admin:root
    fi
    # 判断用户是否存在
    curl -s -u "$user_pass" -H 'Accept: application/json' http://${ZONE1_RS_IP}:${OCP_PORT}/api/v2/iam/users | grep -q "\"username\":\"$OCP_GRAFANA_USER\""
    if [ $? -eq 0 ]; then # user exist
        curl -s -u "$OCP_GRAFANA_USER:$OCP_GRAFANA_PASSWORD" -H 'Accept: application/json' http://${ZONE1_RS_IP}:${OCP_PORT}/api/v2/profiles/me | grep -q "\"successful\":true"
        if [ $? -ne 0 ]; then  # user access failed
            antman_log "grafana user/password can not access ocp, maybe wrong password?" "ERROR"
            exit 1
        fi
    else  # user not exist, create it
        local pubkey payload
        if [ "$gt_320" = True ]; then
            pubkey=$(curl -s -H 'Accept: application/json' http://${ZONE1_RS_IP}:${OCP_PORT}/api/v2/loginKey | python -c "import json, sys; d=json.loads(raw_input()); print json.dumps(d['data']['publicKey']) if d['successful'] is True else sys.exit(1) ")
            [ $? -ne 0 ] && { antman_log "Can not get the publickey of grafana user, create user failed." "ERROR"; exit 1; }
            pubkey=$(eval echo -n $pubkey) # delete quote

            if [ -z "$pubkey" ]; then  # 未开启加密密码
                payload="{\"username\":\"$OCP_GRAFANA_USER\",\"password\":\"$OCP_GRAFANA_PASSWORD\",\"email\":\"$OCP_GRAFANA_USER@changeme.com\",\"roles\":[101]}"  # Profile user
            else
                echo -e "-----BEGIN PUBLIC KEY-----\n$pubkey\n-----END PUBLIC KEY-----" > /tmp/"$OCP_GRAFANA_USER".pub
                local encrypted_password=$(echo -n "$OCP_GRAFANA_PASSWORD" | openssl rsautl -encrypt -inkey /tmp/"$OCP_GRAFANA_USER".pub -pubin | base64| tr -d "\n")
                payload="{\"username\":\"$OCP_GRAFANA_USER\",\"password\":\"$encrypted_password\",\"email\":\"$OCP_GRAFANA_USER@changeme.com\",\"roles\":[101]}" 
            fi
        else
            payload="{\"username\":\"$OCP_GRAFANA_USER\",\"password\":\"$OCP_GRAFANA_PASSWORD\",\"email\":\"$OCP_GRAFANA_USER@changeme.com\",\"roles\":[101]}"
        fi
        curl -s -X POST --user "$user_pass" --header 'Accept: application/json' --header 'Content-Type: application/json' --data "$payload"  http://${ZONE1_RS_IP}:${OCP_PORT}/api/v2/iam/users | grep -q "\"successful\":true"
        [ $? -ne 0 ] && { antman_log "Create grafana user failed, url is: http://${ZONE1_RS_IP}:${OCP_PORT}/api/v2/iam/users , payload is: $payload" "ERROR"; exit 1; }
    fi

    # 拉起镜像
    if [ -n "$OCP_GRAFANA_IMAGE_PACKAGE" ]; then
        _scp "$OCP_GRAFANA_IP" $base_dir/"$OCP_GRAFANA_IMAGE_PACKAGE"
        _ssh "$OCP_GRAFANA_IP" "docker load -i $base_dir/$OCP_GRAFANA_IMAGE_PACKAGE"
    else
        antman_log "OCP_GRAFANA_IMAGE_PACKAGE is empty, skip docker load"
    fi
    local ocp_target_str
    for ip in ${ZONE_RS_IP_LIST[@]}
    do
        ocp_target_str+="$ip:$OCP_PORT,"
    done
    ocp_target_str=${ocp_target_str%,}
    local cmd="docker run -d --net host -e PROMETHEUS_SERVER_HTTP_PORT=$OCP_GRAFANA_PROMETHEUS_PORT -e GRAFANA_SERVER_HTTP_PORT=$OCP_GRAFANA_WEB_PORT -e OCP_BASIC_AUTH_USER=$OCP_GRAFANA_USER -e OCP_BASIC_AUTH_PASS=$OCP_GRAFANA_PASSWORD -e OCP_TARGET_URLS=$ocp_target_str --name ocp_grafana $OCP_GRAFANA_IMAGE_REPO:$OCP_GRAFANA_IMAGE_TAG"
    _ssh "$OCP_GRAFANA_IP" "$cmd" || { antman_log "run [$cmd] on $OCP_GRAFANA_IP failed!" "ERROR"; exit 1; }
    antman_log "install ocp grafana success. Visit http://$OCP_GRAFANA_IP:$OCP_GRAFANA_WEB_PORT for OCP metrics."
}

function clear_step11(){
    antman_log "start cleanup ocp grafana on $OCP_GRAFANA_IP..."
    local container_id=$(_ssh "$OCP_GRAFANA_IP" "docker ps -a --format '{{.ID}}\t{{.Image}}' | grep -w $OCP_GRAFANA_IMAGE_REPO:$OCP_GRAFANA_IMAGE_TAG | awk '{print $1}'")
    if [ -n "$container_id" ]; then
        _ssh  "$OCP_GRAFANA_IP" "docker rm -f $container_id" && antman_log "delete ocp grafana success." || { antman_log "delet ocp grafana failed" "ERROR"; exit 1; }
    else
        antman_log "ocp_grafana is already deleted"
    fi
}

function step12(){
    IFS="," read -r -a ip_array <<<"$OCP_OPENSEARCH_IP_LIST"
    antman_log "start install ocp opensearch on ${ip_array[*]}"
    # 传输镜像
    antman_log "transfer and load image..."
    for ip in "${ip_array[@]}";
    do
        is_ip_legal "OCP opensearch" "$ip"
        local ports=("$OCP_OPENSEARCH_HTTP_PORT" "$OCP_OPENSEARCH_TCP_PORT" "$OCP_OPENSEARCH_CEREBRO_PORT" "$OCP_OPENSEARCH_EXPORTER_PORT")
        for p in "${ports[@]}";
        do
            is_port_legal OMS_PORT "$p"
            check_port_in_use "$ip" "$p"
        done
        if [ -n "$OCP_OPENSEARCH_IMAGE_PACKAGE" ]; then
            if _ssh "$ip" "docker load" < "$base_dir/$OCP_OPENSEARCH_IMAGE_PACKAGE"; then
                antman_log "docker load on $ip success"
            else
                antman_log "docker load on $ip failed" "ERROR"
                exit 1
            fi
        else
            antman_log "OCP_OPENSEARCH_IMAGE_PACKAGE is empty, skip docker load on $ip"
        fi
    done
    antman_log "start ocp opensearch container..."
    local cmd
    cmd="mkdir -p $OCP_OPENSEARCH_DATA_DIR; setfacl -dm 'u:500:rwx' $OCP_OPENSEARCH_DATA_DIR; setfacl -Rm 'u:500:rwx' $OCP_OPENSEARCH_DATA_DIR; docker run -d --net host --name ocp_opensearch --ulimit nofile=65536:65536 --ulimit memlock=-1:-1 \
-v $OCP_OPENSEARCH_DATA_DIR:/data/1/opensearch -e OPENSEARCH_USERNAME=$OCP_OPENSEARCH_USER -e OPENSEARCH_PASSWORD=$OCP_OPENSEARCH_PASSWORD \
-e OPENSEARCH_NODE_URLS=$OCP_OPENSEARCH_IP_LIST -e OPENSEARCH_JVM_HEAP=$OCP_OPENSEARCH_JVM_HEAP -e OPENSEARCH_HTTP_PORT=$OCP_OPENSEARCH_HTTP_PORT \
-e OPENSEARCH_TCP_PORT=$OCP_OPENSEARCH_TCP_PORT -e CEREBRO_PORT=$OCP_OPENSEARCH_CEREBRO_PORT -e ELASTICSEARCH_EXPORTER_PORT=$OCP_OPENSEARCH_EXPORTER_PORT  \
$OCP_OPENSEARCH_IMAGE_REPO:$OCP_OPENSEARCH_IMAGE_TAG"
    antman_log "command is: $cmd"
    for ip in "${ip_array[@]}";
    do
        _ssh "$ip" "$cmd" || { antman_log "run [$cmd] on $ip failed!" "ERROR"; exit 1; }
    done
    # todo: set ocp config properties
    antman_log "install ocp opensearch success. Please visit ocp to set opensearch configs."
}

function clear_step12(){
    IFS="," read -r -a ip_array <<<"$OCP_OPENSEARCH_IP_LIST"
    antman_log "start cleanup ocp opensearch on ${ip_array[*]}"
    for ip in "${ip_array[@]}";
    do
        is_ip_legal "OCP opensearch" "$ip"
        local container_id
        container_id=$(_ssh "$ip" "docker ps -a --format '{{.ID}}\t{{.Image}}' | grep -w $OCP_OPENSEARCH_IMAGE_REPO:$OCP_OPENSEARCH_IMAGE_TAG | awk '{print \$1}'")
        if [ -n "$container_id" ]; then
            _ssh  "$ip" "docker rm -f $container_id" && antman_log "delete ocp opensearch on $ip success." || { antman_log "delet ocp opensearch on $ip failed" "ERROR"; exit 1; }
        else
            antman_log "ocp_opensearch is already deleted on $ip, you may need to delete datadir $OCP_OPENSEARCH_DATA_DIR manually"
        fi
    done
    antman_log "cleanup ocp opensearch container success."
}

# init uninstall_status.log
for STEP in $CLEAR_STEPS
do
    case "$STEP" in
        "2")
            if [[ "$LB_MODE" == "dns" ]]; then
                insert_status_log "uninstall" "$STEP" "uninstall_ob_dns" "${DNS_SERVER_IP_LIST_STR}" "pending"
            elif [[ "$LB_MODE" == "haproxy" ]]; then
                insert_status_log "uninstall" "$STEP" "uninstall_ob_haproxy" "${ZONE_RS_IP_LIST_STR}" "pending"
            elif [[ "$LB_MODE" == "nlb" ]]; then
                insert_status_log "uninstall" "$STEP" "uninstall_nlb" "${NLB_IP_LIST}" "pending"
            fi
            ;;
        "3")
            insert_status_log "uninstall" "$STEP" "uninstall_ob" "${ZONE_RS_IP_LIST_STR}" "pending"
            ;;
        "4")
            insert_status_log "uninstall" "$STEP" "uninit_metadb" ${ZONE1_RS_IP} "pending"
            ;;
        "5")
            insert_status_log "uninstall" "$STEP" "uninstall_tmp_ocp" ${ZONE1_RS_IP} "pending"
            ;;
        "6")
            insert_status_log "uninstall" "$STEP" "uninstall_obproxy" "${ZONE_RS_IP_LIST_STR}" "pending"
            ;;
        "7")
            insert_status_log "uninstall" "$STEP" "uninstall_ocp" "${ZONE_RS_IP_LIST_STR}" "pending"
            ;;
        "9")
            insert_status_log "uninstall" "$STEP" "uninstall_oms" ${OMS_IP_LIST} "pending"
            ;;
        "10")
            insert_status_log "uninstall" "$STEP" "uninstall_odc" ${ZONE1_RS_IP} "pending"
            ;;
        "11")
            insert_status_log "uninstall" "$STEP" "uninstall_ocp_grafana" ${ZONE1_RS_IP} "pending"
            ;;
        "12")
            insert_status_log "uninstall" "$STEP" "uninstall_ocp_opensearch" ${ZONE1_RS_IP} "pending"
            ;;
        *)
            continue
            ;;
    esac
done

# init install_status.log
for STEP in $INSTALL_STEPS
do
    case "$STEP" in
        "1")
            insert_status_log "install" "$STEP" "ssh_auth" ${ZONE1_RS_IP} "pending"
            ;;
        "2")
            if [[ "$LB_MODE" == "dns" ]]; then
                insert_status_log "install" "$STEP" "install_ob_dns" "${DNS_SERVER_IP_LIST_STR}" "pending"
                if [[ $(echo $SINGLE_OCP_MODE | tr '[a-z]' '[A-Z]') != "TRUE" ]]; then
                    insert_status_log "install" "$STEP" "check_lb_connection" ${ZONE1_RS_IP} "pending"
                fi
            elif [[ "$LB_MODE" == "haproxy" ]]; then
                insert_status_log "install" "$STEP" "validate_network" ${ZONE1_RS_IP} "pending"
                insert_status_log "install" "$STEP" "install_ob_haproxy" "${ZONE_RS_IP_LIST_STR}" "pending"
                insert_status_log "install" "$STEP" "check_lb_connection" ${ZONE1_RS_IP} "pending"
            elif [[ "$LB_MODE" == "nlb" ]]; then
                insert_status_log "install" "$STEP" "install_nlb" "${NLB_IP_LIST}" "pending"
            fi
            ;;
        "3")
            insert_status_log "install" "$STEP" "scp_package_ob" ${ZONE1_RS_IP} "pending"
            insert_status_log "install" "$STEP" "install_ob" "${ZONE_RS_IP_LIST_STR}" "pending"
            insert_status_log "install" "$STEP" "bootstrap_ob" ${ZONE1_RS_IP} "pending"
            ;;
        "4")
            insert_status_log "install" "$STEP" "init_metadb" ${ZONE1_RS_IP} "pending"
            ;;
        "5")
            insert_status_log "install" "$STEP" "install_tmp_ocp" ${ZONE1_RS_IP} "pending"
            ;;
        "6")
            insert_status_log "install" "$STEP" "wait_ocp_ready" ${ZONE1_RS_IP} "pending"
            insert_status_log "install" "$STEP" "install_obproxy" "${ZONE_RS_IP_LIST_STR}" "pending"
            ;;
        "7")
            insert_status_log "install" "$STEP" "install_ocp" "${ZONE_RS_IP_LIST_STR}" "pending"
            ;;
        "8")
            insert_status_log "install" "$STEP" "post_check_service" ${ZONE1_RS_IP} "pending"
            ;;
        "9")
            insert_status_log "install" "$STEP" "install_oms" ${OMS_IP_LIST} "pending"
            ;;
        "10")
            insert_status_log "install" "$STEP" "install_odc" ${ZONE1_RS_IP} "pending"
            ;;
        "11")
            insert_status_log "install" "$STEP" "install_ocp_grafana" ${ZONE1_RS_IP} "pending"
            ;;
        "12")
            insert_status_log "install" "$STEP" "install_ocp_opensearch" ${ZONE1_RS_IP} "pending"
            ;;
        *)
            continue
            ;;
    esac
done

for STEP in $CLEAR_STEPS
do
    eval clear_step${STEP}
done


for STEP in $INSTALL_STEPS
do
    eval step${STEP}
done

# 20220420 add replace function
if [[ -n $REPLACE_PRODUCT ]] && [[ -n $OLD_PRODUCT_REPO_TAG ]]; then
   case "${REPLACE_PRODUCT}" in
       ocp)
            antman_log "replace ocp container on ${ZONE_RS_IP_LIST[*]}..."
            for ip in "${ZONE_RS_IP_LIST[@]}";
            do
                replace_container "$ip" "$OLD_PRODUCT_REPO_TAG" "$OCP_IMAGE_REPO:$OCP_IMAGE_TAG" "$OCP_DOCKER_IMAGE_PACKAGE" ocp
            done
       ;;
       odc)
           antman_log "replace odc container on ${ZONE_RS_IP_LIST[*]}..."
            for ip in "${ZONE_RS_IP_LIST[@]}";
            do
                replace_container "$ip" "$OLD_PRODUCT_REPO_TAG" "$ODC_IMAGE_REPO:$ODC_IMAGE_TAG" "$ODC_DOCKER_IMAGE_PACKAGE" odc
            done
       ;;
       oms)
           antman_log "replace oms container on ${OMS_IP_ARRAY[*]}..."
            for ip in "${OMS_IP_ARRAY[@]}";
            do
                replace_container "$ip" "$OLD_PRODUCT_REPO_TAG" "$OMS_IMAGE_REPO:$OMS_IMAGE_TAG" "$OMS_DOCKER_IMAGE_PACKAGE" oms
            done
       ;;
       *)
           echo "unknown product (none of above)"
       ;;
   esac
   
fi