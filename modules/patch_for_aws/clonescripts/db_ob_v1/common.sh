#!/bin/bash


#
# check red-hat release 6
#
is_rhel_6 ()
{
  if [[ -f /etc/redhat-release ]]; then
    if [[ `grep "release 6" /etc/redhat-release | wc -l` -gt 0 ]]; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

#
# check red-hat release 7
#
is_rhel_7 ()
{
  if [[ -f /etc/redhat-release ]]; then
    if [[ `grep "release 7" /etc/redhat-release | wc -l` -gt 0 ]]; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

is_centos7_or_uosc(){
    if [ -f /etc/redhat-release ]; then
        return 0
    elif grep -Ewiq 'uos|uniontech' /etc/system-release && grep -q "=c" /etc/os-version ; then
        return 0
    elif grep -Ewiq 'Amazon' /etc/system-release ; then
        return 0
    else
        return 1
    fi
}

is_kylin_like(){
  if [[ -f /etc/kylin-release ]]; then
    return 0
  elif grep -Ewiq 'uos|uniontech' /etc/system-release && grep -q "=[ae]" /etc/os-version ; then
    return 0
  elif grep -Eqi 'redflag|openeuler' /etc/os-release; then
    return 0
  else
    return 1
  fi
}

is_suse(){
  if [[ -f /etc/SuSE-release ]]; then
    return 0
  else
    return 1
  fi
}

is_debian() {
  which dpkg > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    return 0
  else
    return 1
  fi
}

# check if processer is ARM
is_arm() {
    processer_type=$(uname -m)
    if [[ $(echo $processer_type | grep -i aarch64) != "" ]]; then
        return 0
    else
        return 1
    fi
}

set_PATH_LANG()
{
## PATH setting:
export PATH="$PATH:/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/admin/oceanbase/bin"

if [[ ! `grep '^export PATH=' /etc/profile` ]];then
        echo >>/etc/profile
        echo "export PATH=\"\$PATH:/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/admin/oceanbase/bin\"" >>/etc/profile
else
        sed -i "s/^export PATH\=.*/export PATH=\"\$PATH:\/sbin:\/usr\/sbin:\/bin:\/usr\/bin:\/usr\/local\/sbin:\/usr\/local\/bin:\/home\/admin\/oceanbase\/bin\"/g" /etc/profile
fi

## LANG setting:
export LANG=en_US.UTF-8
if is_rhel_6; then
  sed -i "s/^LANG\=.*/LANG=\"en_US.UTF-8\"/g" /etc/sysconfig/i18n
fi

if [[ ! `grep '^export LANG\=' /etc/profile` ]];then
        echo >>/etc/profile
        echo "export LANG=\"en_US.UTF-8\"" >>/etc/profile
else
        sed -i "s/^export LANG\=.*/export LANG=\"en_US.UTF-8\"/g" /etc/profile
fi
##

export PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/admin/oceanbase/bin"
}

set_PATH_LANG

CLONEHOME="/usr/local/clonescripts/db_ob_v1"
CLONEVAR="/var/clone"
CLONEDIST="$CLONEHOME/dist"
SCRIPTDIR="$CLONEHOME/postinstall"
CHECKDIR="$CLONEHOME/check"
STAGEDIR="${CLONEVAR}/stage"
LOGFILE="${CLONEVAR}/clone.log"
ERRFILE="${CLONEVAR}/clone.err"
