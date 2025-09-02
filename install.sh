#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# 字体颜色配置
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# 变量
shell_version="1.0.0"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
random_num=$((RANDOM % 12 + 4))

# 脚本初始化
set -e          # 遇到错误退出
set -u          # 遇到未定义变量退出
set -o pipefail # 管道命令错误退出

# 打印信息
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

# 打印错误
function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

# 检查root权限
function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "当前用户是 root 用户，开始安装流程"
  else
    print_error "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本"
    exit 1
  fi
}

# 检查系统
function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "当前系统为 Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "当前系统为 Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    apt update

  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    apt update
    
  else
    print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
    exit 1
  fi
}

# 安装依赖
function dependency_install() {
  ${INS} lsof tar
  judge "安装 lsof tar"

  ${INS} unzip
  judge "安装 unzip"

  ${INS} curl
  judge "安装 curl"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  # 防止部分系统xray的默认bin目录缺失
  mkdir /usr/local/bin >/dev/null 2>&1
}

# 基础优化
function basic_optimization() {
  # 最大文件打开数
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # RedHat 系发行版关闭 SELinux
  if [[ "${ID}" == "centos" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}

# IP检查
function domain_check() {
  print_ok "正在获取本机 IP 地址信息，请耐心等待"
    
  # 获取本机IPv4和IPv6地址
  local_ipv4=$(curl -4s ip.sb 2>/dev/null || curl -4s icanhazip.com 2>/dev/null || print_error "无法获取IPv4地址")
  local_ipv6=$(curl -6s ip.sb 2>/dev/null || curl -6s icanhazip.com 2>/dev/null || print_error "无法获取IPv6地址")
    
  # 显示IP信息
  echo -e "本机公网 IPv4 地址： ${local_ipv4}"
  echo -e "本机公网 IPv6 地址： ${local_ipv6}"
    
  # 存储IP地址
  if [[ "${local_ipv4}" != "无法获取IPv4地址" ]]; then
    domain_ip="${local_ipv4}"
    print_ok "将使用 IPv4 地址: ${domain_ip}"
  elif [[ "${local_ipv6}" != "无法获取IPv6地址" ]]; then
    domain_ip="${local_ipv6}"
    print_ok "识别为 IPv6 Only 的 VPS，将使用 IPv6 地址: ${domain_ip}"
  else
    print_error "无法获取有效的 IP 地址"
    exit 1
  fi
    
  sleep 2
    
  print_ok "IP地址获取完成"
}

# 端口检查
function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 端口未被占用"
    sleep 1
  else
    print_error "检测到 $1 端口被占用，以下为 $1 端口占用信息"
    lsof -i:"$1"
    print_error "5s 后将尝试自动 kill 占用进程"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill 完成"
    sleep 1
  fi
}

# 安装进度提示
judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 完成"
    sleep 1
  else
    print_error "$1 失败"
    exit 1
  fi
}

function install_xray() {
  # is_root
  # system_check
  # dependency_install
  # basic_optimization
  # domain_check
  port_exist_check 80
  # xray_install
  # configure_xray
  # nginx_install
  # configure_nginx
  # configure_web
  # generate_certificate
  # ssl_judge_and_install
  # restart_all
  # basic_information
}
menu() {
  # update_sh
  # shell_mode_check
  echo -e "\t Xray 安装管理脚本 ${Red}[${shell_version}]${Font}"

  # echo -e "当前已安装版本：${shell_mode}"
  echo -e "—————————————— 安装向导 ——————————————"""
  # echo -e "${Green}0.${Font}  升级 脚本"
  echo -e "${Green}1.${Font}  安装 Xray (VLESS-TCP-XTLS-Vision-REALITY (without being stolen))"
  echo -e "—————————————— 配置变更 ——————————————"
  echo -e "${Green}11.${Font} 变更 UUID"
  echo -e "${Green}13.${Font} 变更 连接端口"
  echo -e "—————————————— 查看信息 ——————————————"
  echo -e "${Green}21.${Font} 查看 实时访问日志"
  echo -e "${Green}22.${Font} 查看 实时错误日志"
  echo -e "${Green}23.${Font} 查看 Xray 配置链接"
  #    echo -e "${Green}23.${Font}  查看 V2Ray 配置信息"
  echo -e "—————————————— 其他选项 ——————————————"
  echo -e "${Green}33.${Font} 卸载 Xray"
  echo -e "${Green}34.${Font} 更新 Xray-core"
  echo -e "${Green}35.${Font} 安装 Xray-core 测试版 (Pre)"
  echo -e "${Green}40.${Font} 退出"
  read -rp "请输入数字：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    install_xray_ws
    ;;
  11)
    read -rp "请输入 UUID:" UUID
    if [[ ${shell_mode} == "tcp" ]]; then
      modify_UUID
    elif [[ ${shell_mode} == "ws" ]]; then
      modify_UUID
      modify_UUID_ws
    fi
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    if [[ ${shell_mode} == "ws" ]]; then
      read -rp "请输入路径(示例：/wulabing/ 要求两侧都包含 /):" WS_PATH
      modify_fallback_ws
      modify_ws
      restart_all
    else
      print_error "当前模式不是 Websocket 模式"
    fi
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "xray 配置文件不存在"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  32)
    mtproxy_sh
    ;;
  33)
    source '/etc/os-release'
    xray_uninstall
    ;;
  34)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  35)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  36)
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "请输入正确的数字"
    ;;
  esac
}
menu "$@"
