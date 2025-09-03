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

# 检查shell模式
function shell_mode_check() {
  if [ -f ${xray_conf_dir}/config.json ]; then
    security_type=$(grep -A 20 '"streamSettings"' ${xray_conf_dir}/config.json | grep -A 10 '"security"' | awk -F'"' '{print $4}' | head -1)
    network_type=$(grep -A 20 '"streamSettings"' ${xray_conf_dir}/config.json | grep -A 10 '"network"' | awk -F'"' '{print $4}' | head -1)
    
    security_type=${security_type:-"none"}
    network_type=${network_type:-"tcp"}
    
    if [ "$security_type" = "reality" ]; then
      shell_mode="reality"
    elif [ "$network_type" = "ws" ] || [ "$network_type" = "websocket" ]; then
      shell_mode="ws"
    else
      shell_mode="tcp"
    fi
  else
    shell_mode="None"
  fi
}

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
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel jq
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev jq
  fi
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

# 安装xray
function xray_install() {
  print_ok "安装 Xray"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  judge "Xray 安装"
}

# 生成随机端口、UUID、privateKey、publicKey、shortIds
function generate_random_port_generate_uuid_privateKey_publicKey_shortIds() {
    local min_port=30000
    local max_port=60000
    local port_range=$((max_port - min_port + 1))
    
    # 生成随机端口
    domain_port=$((RANDOM % port_range + min_port))

    domain_uuid=$(xray uuid)
    xray x25519 > /tmp/keys.txt
    domain_privateKey=$(grep "PrivateKey" /tmp/keys.txt | awk '{print $2}')
    domain_publicKey=$(grep "Password" /tmp/keys.txt | awk '{print $2}')
    domain_shortIds=$(openssl rand -hex 8)
}

# 下载配置文件
function configure_xray() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/2253845067/Xray_install/${github_branch}/config.json
  modify_port_modify_uuid_privateKey_publicKey_shortIds
}

# 更改配置文件
function xray_tmp_config_file_check_and_use() {
  if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
    mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
  else
    print_error "xray 配置文件修改异常"
  fi
}

# 修改端口、UUID、privateKey、publicKey、shortIds
function modify_port_modify_uuid_privateKey_publicKey_shortIds() {
  jq --arg port "$domain_port" \
     --arg uuid "$domain_uuid" \
     --arg privateKey "$domain_privateKey" \
     --arg publicKey "$domain_publicKey" \
     --arg shortIds "$domain_shortIds" '
  setpath(["inbounds",0,"port"]; $port | tonumber) |
  setpath(["inbounds",0,"settings","port"]; $port | tonumber) |
  setpath(["inbounds",1,"port"]; $port | tonumber) |
  setpath(["inbounds",1,"settings","clients",0,"id"]; $uuid) |
  setpath(["inbounds",1,"streamSettings","realitySettings","privateKey"]; $privateKey) |
  setpath(["inbounds",1,"streamSettings","realitySettings","publicKey"]; $publicKey) |
  setpath(["inbounds",1,"streamSettings","realitySettings","shortIds"]; ["", $shortIds])
  ' ${xray_conf_dir}/config.json > ${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray 端口、UUID、privateKey、publicKey、shortIds 修改"
}

# 重启xray
function restart_all() {
  systemctl restart xray
  systemctl enable xray
  judge "Xray 启动"
}

# 基本信息
function basic_information() {
  print_ok "VLESS-TCP-XTLS-Vision-REALITY (without being stolen) 安装成功"
  vless_tcp_xtls-vision_reality_information
  vless_tcp_xtls-vision_reality_link
}

# 信息
function vless_tcp_xtls-vision_reality_information() {
  # 获取本机IPv4和IPv6地址
  local_ipv4=$(curl -4s ip.sb 2>/dev/null || curl -4s icanhazip.com 2>/dev/null || print_error "无法获取IPv4地址")
  local_ipv6=$(curl -6s ip.sb 2>/dev/null || curl -6s icanhazip.com 2>/dev/null || print_error "无法获取IPv6地址")
    
  # 存储IP地址
  if [[ "${local_ipv4}" != "无法获取IPv4地址" ]]; then
    domain_ip="${local_ipv4}"
  elif [[ "${local_ipv6}" != "无法获取IPv6地址" ]]; then
    domain_ip="${local_ipv6}"
  else
    print_error "无法获取有效的 IP 地址"
    exit 1
  fi

  domain_port=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  domain_uuid=$(cat ${xray_conf_dir}/config.json | jq -r '.inbounds[1].settings.clients[0].id')
  domain_flow=$(cat ${xray_conf_dir}/config.json | jq -r '.inbounds[1].settings.clients[0].flow')
  domain_sni=$(cat ${xray_conf_dir}/config.json | jq -r '.inbounds[1].streamSettings.realitySettings.serverNames[0]')
  domain_publicKey=$(cat ${xray_conf_dir}/config.json | jq -r '.inbounds[1].streamSettings.realitySettings.publicKey')
  domain_shortIds=$(cat ${xray_conf_dir}/config.json | jq -r '.inbounds[1].streamSettings.realitySettings.shortIds[1]')

  echo -e "${Red} Xray 配置信息 ${Font}"
  echo -e "${Red} 地址（address）:${Font}  $domain_ip"
  echo -e "${Red} 端口（port）：${Font}  $domain_port"
  echo -e "${Red} 用户 ID（UUID）：${Font} $domain_uuid"
  echo -e "${Red} 流控（flow）：${Font} $domain_flow"
  echo -e "${Red} 加密方式（security）：${Font} none "
  echo -e "${Red} 传输协议（network）：${Font} tcp "
  echo -e "${Red} 伪装类型（type）：${Font} none "
  echo -e "${Red} 底层传输安全：${Font} reality"
  echo -e "${Red} SNI：${Font} $domain_sni"
  echo -e "${Red} Fingerprint：${Font} chrome"
  echo -e "${Red} PublicKey：${Font} $domain_publicKey"
  echo -e "${Red} ShortIds：${Font} $domain_shortIds"
}

# 信息
function vless_tcp_xtls-vision_reality_link() {
  print_ok "URL 链接"
  print_ok "vless://$domain_uuid@$domain_ip:$domain_port?encryption=none&flow=$domain_flow&security=reality&sni=$domain_sni&fp=chrome&pbk=$domain_publicKey&sid=$domain_shortIds&spx=%2F&type=tcp&headerType=none#dokodemo-in"
  print_ok "-------------------------------------------------"
  print_ok "URL 二维码 (VLESS + TCP + TLS) （请在浏览器中访问）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$domain_uuid@$domain_ip:$domain_port?encryption=none&flow=$domain_flow&security=reality&sni=$domain_sni&fp=chrome&pbk=$domain_publicKey&sid=$domain_shortIds&spx=%2F&type=tcp&headerType=none#dokodemo-in"
}

# 卸载xray
function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  print_ok "卸载完成"
  exit 0
}

# 变更UUID
function modify_UUID() {
  read -rp "请输入 UUID (直接回车将自动生成): " UUID
  if [ -z "$UUID" ]; then
    # 自动生成 UUID
    if command -v xray &> /dev/null; then
        UUID=$(xray uuid)
    else
        UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(............\)/\1-\2-\3-\4/')
    fi
    echo "已自动生成 UUID: $UUID"
  fi

  # 验证 UUID 格式（基本验证）
  if [[ ! "$UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "错误: UUID 格式不正确"
    exit 1
  fi

  # 使用 jq 的安全方式修改配置
  jq --arg uuid "$UUID" 'setpath(["inbounds",1,"settings","clients",0,"id"]; $uuid)' ${xray_conf_dir}/config.json > ${xray_conf_dir}/config_tmp.json

  # 检查并应用配置
  xray_tmp_config_file_check_and_use
  judge "Xray TCP UUID 修改"
  restart_all
}

# 变更端口
function modify_port() {
  read -rp "请输入端口 (直接回车将自动生成): " port
  if [ -z "$port" ]; then
    local min_port=30000
    local max_port=60000
    local port_range=$((max_port - min_port + 1))
    
    # 生成随机端口
    port=$((RANDOM % port_range + min_port))
  fi

  echo "已自动生成 端口: $port"

  jq --arg port "$port" 'setpath(["inbounds",0,"port"]; $port | tonumber) | setpath(["inbounds",0,"settings","port"]; $port | tonumber) | setpath(["inbounds",1,"port"]; $port | tonumber)' ${xray_conf_dir}/config.json > ${xray_conf_dir}/config_tmp.json

  xray_tmp_config_file_check_and_use
  judge "Xray 端口修改"
  restart_all
}

# 更新脚本
function update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/2253845067/Xray_install/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "存在新版本，是否更新 [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/2253845067/Xray_install/${github_branch}/install.sh
      print_ok "更新完成"
      print_ok "您可以通过 bash $0 执行本程序"
      exit 0
      ;;
    *) ;;
    esac
  else
    print_ok "当前版本为最新版本"
    print_ok "您可以通过 bash $0 执行本程序"
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
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  xray_install
  generate_random_port_generate_uuid_privateKey_publicKey_shortIds
  configure_xray
  restart_all
  basic_information
}
menu() {
  update_sh
  shell_mode_check
  echo -e "\t Xray 安装管理脚本 ${Red}[${shell_version}]${Font}"

  echo -e "当前已安装版本：${shell_mode}"
  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}0.${Font}  升级 脚本"
  echo -e "${Green}1.${Font}  安装 Xray (VLESS-TCP-XTLS-Vision-REALITY (without being stolen))"
  echo -e "—————————————— 配置变更 ——————————————"
  echo -e "${Green}11.${Font} 变更 UUID"
  echo -e "${Green}12.${Font} 变更 连接端口"
  echo -e "—————————————— 查看信息 ——————————————"
  echo -e "${Green}21.${Font} 查看 实时访问日志"
  echo -e "${Green}22.${Font} 查看 实时错误日志"
  echo -e "${Green}23.${Font} 查看 Xray 配置链接"
  echo -e "—————————————— 其他选项 ——————————————"
  echo -e "${Green}31.${Font} 卸载 Xray"
  echo -e "${Green}32.${Font} 更新 Xray-core"
  echo -e "${Green}33.${Font} 安装 Xray-core 测试版 (Pre)"
  echo -e "${Green}40.${Font} 退出"
  read -rp "请输入数字：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  11)
    modify_UUID
    basic_information
    ;;
  12)
    modify_port
    basic_information
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      basic_information
    else
      print_error "xray 配置文件不存在"
    fi
    ;;
  31)
    source '/etc/os-release'
    xray_uninstall
    ;;
  32)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    restart_all
    ;;
  33)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta
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
