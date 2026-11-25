#!/bin/bash
# =========================================================
# VPS 全自动系统级 WARP 动态分流解锁脚本
# (单栈 IPv6 / 双栈 / IPv4 自适应高精度版)
#
# 核心特性:
# 1. 深度适配单栈 IPv6 (IPv6-Only VPS):
#    - 全自动识别单栈 IPv6、双栈与 IPv4 网络环境
#    - Cloudflare API 通信自适应走 IPv6 / IPv4
#    - WireGuard 端点智能优选 Anycast IPv6 ([2606:4700:d0::...])
#    - Dnsmasq 上游双栈/IPv6 DNS 防断网兜底
#    - 单栈 IPv6 下将 warp0 设为全局默认 IPv4 网关，彻底打通 IPv4 出网访问
# 2. 权威高精度送中判定：
#    - 深度对齐 NodeQuality / IPQuality / 融合怪 行业通用判定算法
#    - 基于 YouTube Premium 原生接口与 Google 搜索多维交叉验证
#    - 彻底解决现代 Google 搜索不发生 302 重定向导致的误判漏判
# 3. 完整资产分流库：
#    - YouTube 全家桶 (含视频流 googlevideo.com / 解决 [CN] 送中)
#    - Google 搜索、API、账户、Play商店及 Android CDN
#    - Google AI 矩阵 (Gemini / Antigravity / AI Studio / DeepMind)
#    - OpenAI / ChatGPT / Claude 全系列
# 4. 零配置与防失效保障：
#    - Dnsmasq 动态捕获 IP 并入库 Ipset 策略路由，IP 轮换永不失效
#    - 锁定 /etc/resolv.conf 属性，彻底防止 VPS 重启或 DHCP 覆写失效
#    - 双栈 IPv4/IPv6 TCPMSS 钳制与 QUIC 拦截，杜绝握手断流
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}[错误] 请使用 root 权限运行此脚本！${NC}"; exit 1; }

# ---------------------------------------------------------
# 网络环境检测：智能识别单栈 IPv6、双栈或单栈 IPv4
# ---------------------------------------------------------
detect_network_environment() {
    IS_V6_ONLY=0
    HAS_V4=0
    HAS_V6=0

    # 排除 warp, wg, tun 等虚拟网卡，提取原生物理/默认网卡
    local PHYS_V4_IFACE PHYS_V6_IFACE
    PHYS_V4_IFACE=$(ip -4 route show default 2>/dev/null | grep -Ev '\bdev (warp|wg|tun)[^ ]*' | grep -oP 'dev \K\S+' | head -n 1)
    PHYS_V6_IFACE=$(ip -6 route show default 2>/dev/null | grep -Ev '\bdev (warp|wg|tun)[^ ]*' | grep -oP 'dev \K\S+' | head -n 1)

    DEFAULT_IFACE="$PHYS_V4_IFACE"
    [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="$PHYS_V6_IFACE"
    [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE=$(ip route show default 2>/dev/null | grep -Ev '\bdev (warp|wg|tun)[^ ]*' | awk '{print $5}' | head -n 1)
    [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE=$(ip link show 2>/dev/null | grep -E '^[0-9]+: (eth|ens|enp|eno|venet)' | awk -F': ' '{print $2}' | cut -d'@' -f1 | head -n 1)

    local IFACE_V4_ARG="" IFACE_V6_ARG=""
    [ -n "$PHYS_V4_IFACE" ] && IFACE_V4_ARG="--interface $PHYS_V4_IFACE"
    [ -n "$PHYS_V6_IFACE" ] && IFACE_V6_ARG="--interface $PHYS_V6_IFACE"

    # 检测原生 IPv4 默认路由与出口连通性 (必须排除 warp/wg/tun 干扰)
    if [ -n "$PHYS_V4_IFACE" ]; then
        if curl -4 -s -m 3 --connect-timeout 2 $IFACE_V4_ARG https://api.cloudflareclient.com >/dev/null 2>&1 || \
           curl -4 -s -m 3 --connect-timeout 2 $IFACE_V4_ARG https://1.1.1.1 >/dev/null 2>&1; then
            HAS_V4=1
        fi
    elif [ -n "$DEFAULT_IFACE" ] && (curl -4 -s -m 3 --connect-timeout 2 --interface "$DEFAULT_IFACE" https://api.cloudflareclient.com >/dev/null 2>&1 || \
                                     curl -4 -s -m 3 --connect-timeout 2 --interface "$DEFAULT_IFACE" https://1.1.1.1 >/dev/null 2>&1); then
        HAS_V4=1
    fi

    # 检测原生 IPv6 默认路由与出口连通性
    if [ -n "$PHYS_V6_IFACE" ]; then
        if curl -6 -s -m 3 --connect-timeout 2 $IFACE_V6_ARG https://api.cloudflareclient.com >/dev/null 2>&1 || \
           curl -6 -s -m 3 --connect-timeout 2 $IFACE_V6_ARG https://[2606:4700:4700::1111] >/dev/null 2>&1; then
            HAS_V6=1
        fi
    elif curl -6 -s -m 3 --connect-timeout 2 https://api.cloudflareclient.com >/dev/null 2>&1 || \
         curl -6 -s -m 3 --connect-timeout 2 https://[2606:4700:4700::1111] >/dev/null 2>&1; then
        HAS_V6=1
    fi

    if [ $HAS_V4 -eq 0 ] && [ $HAS_V6 -eq 1 ]; then
        IS_V6_ONLY=1
        CF_CURL_OPT="-6"
        [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="$PHYS_V6_IFACE"
        # 单栈 IPv6 专属 Anycast WARP 端点
        WARP_ENDPOINTS=(
            "[2606:4700:d0::a29f:c001]:2408"
            "[2606:4700:d0::a29f:c001]:500"
            "[2606:4700:d0::a29f:c10a]:2408"
            "[2606:4700:d0::a29f:c10a]:500"
            "[2606:4700:d1::a29f:c001]:2408"
            "[2606:4700:d1::a29f:c101]:2408"
        )
    else
        CF_CURL_OPT=""
        # 双栈 / IPv4 默认端点 (含 IPv6 Anycast 备选)
        WARP_ENDPOINTS=(
            "162.159.192.1:2408"
            "[2606:4700:d0::a29f:c001]:2408"
            "162.159.193.10:2408"
            "[2606:4700:d0::a29f:c10a]:2408"
            "162.159.192.1:500"
            "188.114.96.1:2408"
        )
    fi
    [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
}

detect_network_environment

# WARP 的两套地址始终保留供隧道诊断；策略决定哪些协议实际走 WARP。
WARP_POLICY_FILE=/etc/warp-unlock/exit-policy.conf
WARP_FAMILY=both
WARP_SCOPE=split
ADDRESS_PREFERENCE=default

load_exit_policy() {
    [ -f "$WARP_POLICY_FILE" ] || return 0
    local value
    value=$(sed -n 's/^family=//p' "$WARP_POLICY_FILE" | head -n 1)
    case "$value" in ipv4|ipv6|both) WARP_FAMILY=$value ;; esac
    value=$(sed -n 's/^scope=//p' "$WARP_POLICY_FILE" | head -n 1)
    case "$value" in split|global) WARP_SCOPE=$value ;; esac
    value=$(sed -n 's/^preference=//p' "$WARP_POLICY_FILE" | head -n 1)
    case "$value" in default|ipv4|ipv6) ADDRESS_PREFERENCE=$value ;; esac
}

select_exit_policy() {
    local answer
    load_exit_policy
    echo "WARP 出口协议：1 IPv4  2 IPv6  3 双栈 (默认 3)"
    read -r -p '请选择 [1-3]: ' answer
    case "${answer:-3}" in 1) WARP_FAMILY=ipv4 ;; 2) WARP_FAMILY=ipv6 ;; 3) WARP_FAMILY=both ;; *) echo '无效选择'; return 1 ;; esac
    echo "出口范围：1 目标服务分流  2 全局 WARP (默认 1)"
    read -r -p '请选择 [1-2]: ' answer
    case "${answer:-1}" in 1) WARP_SCOPE=split ;; 2) WARP_SCOPE=global ;; *) echo '无效选择'; return 1 ;; esac
    echo "本机连接优先级：1 系统默认  2 IPv4 优先  3 IPv6 优先 (默认 1)"
    read -r -p '请选择 [1-3]: ' answer
    case "${answer:-1}" in 1) ADDRESS_PREFERENCE=default ;; 2) ADDRESS_PREFERENCE=ipv4 ;; 3) ADDRESS_PREFERENCE=ipv6 ;; *) echo '无效选择'; return 1 ;; esac
    if [ "$ADDRESS_PREFERENCE" != default ] && [ -f /etc/gai.conf ] &&
       sed '/^# BEGIN warp-unlock preference$/,/^# END warp-unlock preference$/d' /etc/gai.conf | grep -Eq '^[[:space:]]*precedence[[:space:]]'; then
        echo '已有自定义 /etc/gai.conf precedence；请先手动处理，避免覆盖现有优先级。'
        return 1
    fi
    mkdir -p /etc/warp-unlock
    printf 'family=%s\nscope=%s\npreference=%s\n' "$WARP_FAMILY" "$WARP_SCOPE" "$ADDRESS_PREFERENCE" > "$WARP_POLICY_FILE"
}

# 更新 gai.conf 时只移除本脚本管理的区块，保留管理员的其他设置。
apply_address_preference() {
    local tmp
    tmp=$(mktemp /etc/gai.conf.warp.XXXXXX) || return 1
    if [ -f /etc/gai.conf ]; then
        sed '/^# BEGIN warp-unlock preference$/,/^# END warp-unlock preference$/d' /etc/gai.conf > "$tmp"
    fi
    if [ "$ADDRESS_PREFERENCE" != default ]; then
        if grep -Eq '^[[:space:]]*precedence[[:space:]]' "$tmp"; then
            rm -f "$tmp"
            echo '[错误] /etc/gai.conf 已存在自定义 precedence。' >&2
            return 1
        fi
        cat >> "$tmp" << EOF
# BEGIN warp-unlock preference
precedence ::1/128 50
precedence ::/0 40
precedence 2002::/16 30
precedence ::/96 20
precedence ::ffff:0:0/96 $([ "$ADDRESS_PREFERENCE" = ipv4 ] && echo 100 || echo 10)
# END warp-unlock preference
EOF
    fi
    if [ -f /etc/gai.conf ]; then
        cat "$tmp" > /etc/gai.conf || { rm -f "$tmp"; return 1; }
    else
        cp "$tmp" /etc/gai.conf || { rm -f "$tmp"; return 1; }
    fi
    rm -f "$tmp"
}

# ---------------------------------------------------------
# 功能 1：彻底检测并清理老版本脚本及各种历史残留
# ---------------------------------------------------------
auto_clean_old_warp() {
    echo -e "${YELLOW}[深度清理] 正在深度检测并彻底清除所有 WARP 策略路由、防火墙规则及旧版残留...${NC}"
    systemctl stop warp-health.timer warp-health.service 2>/dev/null || true
    systemctl disable warp-health.timer 2>/dev/null || true

    # 0. 向 Cloudflare 释放旧设备注册 (解绑旧 IP 绑定)
    if [ -f /etc/wireguard/warp-account.conf ]; then
        local OLD_ID OLD_TOKEN
        OLD_ID=$(awk -F= '/^DEV_ID=/{print $2}' /etc/wireguard/warp-account.conf 2>/dev/null)
        OLD_TOKEN=$(awk -F= '/^TOKEN=/{print $2}' /etc/wireguard/warp-account.conf 2>/dev/null)
        if [ -n "$OLD_ID" ] && [ -n "$OLD_TOKEN" ]; then
            curl $CF_CURL_OPT -s -m 4 -X DELETE -H "Authorization: Bearer $OLD_TOKEN" "https://api.cloudflareclient.com/v0a2158/reg/$OLD_ID" >/dev/null 2>&1 || true
        fi
    fi

    # 1. 解除 resolv.conf 写保护并优先恢复原生备份 DNS
    chattr -i /etc/resolv.conf 2>/dev/null || true
    if [ -s /etc/resolv.conf.warp.bak ]; then
        cp -f /etc/resolv.conf.warp.bak /etc/resolv.conf
        rm -f /etc/resolv.conf.warp.bak
    else
        cat > /etc/resolv.conf << 'EOF'
nameserver 2001:4860:4860::8888
nameserver 2606:4700:4700::1111
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    fi

    # 2. 停止并禁用所有相关 systemd 服务
    systemctl stop warp-unlock.service warp-svc cloudflare-warp dnsmasq 2>/dev/null || true
    systemctl disable warp-unlock.service warp-svc cloudflare-warp 2>/dev/null || true

    # 3. 停止 WireGuard 接口并强制从内核拔除 warp0 网卡设备
    command -v wg-quick &>/dev/null && wg-quick down warp0 2>/dev/null || true
    command -v warp-cli &>/dev/null && warp-cli disconnect 2>/dev/null || true
    ip link set dev warp0 down 2>/dev/null || true
    ip link del dev warp0 2>/dev/null || true

    # 4. 彻底循环清理所有 IPv4 与 IPv6 iptables / ip6tables 规则
    while iptables -t mangle -D OUTPUT -m set --match-set warp_unlock dst -j MARK --set-mark 51820 2>/dev/null; do :; done
    while iptables -t mangle -D PREROUTING -m set --match-set warp_unlock dst -j MARK --set-mark 51820 2>/dev/null; do :; done
    while iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
    while iptables -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do :; done
    while iptables -t filter -D FORWARD -p udp --dport 443 -m set --match-set warp_unlock dst -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
    while iptables -t filter -D OUTPUT -p udp --dport 443 -m set --match-set warp_unlock dst -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done

    # 清理 IPv6 ip6tables
    while ip6tables -t mangle -D OUTPUT -m set --match-set warp_unlock6 dst -j MARK --set-mark 51820 2>/dev/null; do :; done
    while ip6tables -t mangle -D PREROUTING -m set --match-set warp_unlock6 dst -j MARK --set-mark 51820 2>/dev/null; do :; done
    while ip6tables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
    while ip6tables -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null; do :; done
    while ip6tables -t filter -D FORWARD -p udp --dport 443 -m set --match-set warp_unlock6 dst -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; do :; done
    while ip6tables -t filter -D OUTPUT -p udp --dport 443 -m set --match-set warp_unlock6 dst -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; do :; done

    # 5. 彻底循环清理 IPv4 与 IPv6 策略路由表与规则
    while ip rule del fwmark 51820 lookup 51820 2>/dev/null; do :; done
    while ip rule del fwmark 51819 lookup main priority 80 2>/dev/null; do :; done
    while ip rule del oif warp0 lookup 51820 2>/dev/null; do :; done
    while ip rule del from 172.16.0.0/12 lookup 51820 2>/dev/null; do :; done
    while ip rule del lookup 51820 priority 200 2>/dev/null; do :; done
    while ip rule del lookup 51820 2>/dev/null; do :; done
    while ip -6 rule del fwmark 51820 lookup 51820 2>/dev/null; do :; done
    while ip -6 rule del fwmark 51819 lookup main priority 80 2>/dev/null; do :; done
    while ip -6 rule del oif warp0 lookup 51820 2>/dev/null; do :; done
    while ip -6 rule del lookup 51820 2>/dev/null; do :; done
    while ip rule del priority 190 lookup main suppress_prefixlength 0 2>/dev/null; do :; done
    while ip rule del priority 188 lookup main 2>/dev/null; do :; done
    while ip -6 rule del priority 190 lookup main suppress_prefixlength 0 2>/dev/null; do :; done
    while ip -6 rule del priority 188 lookup main 2>/dev/null; do :; done
    ip route del default dev warp0 table main 2>/dev/null || true
    ip route flush table 51820 2>/dev/null || true
    ip -6 route flush table 51820 2>/dev/null || true

    # 6. 销毁 IPv4 与 IPv6 ipset 集合
    ipset destroy warp_unlock 2>/dev/null || true
    ipset destroy warp_unlock6 2>/dev/null || true

    # 7. 清除所有配置文件、启动脚本、账号缓存及临时扫描脚本
    rm -f /etc/dnsmasq.d/warp_unlock.conf \
          /etc/dnsmasq.d/warp-google.conf \
          /etc/dnsmasq.d/warp*.conf \
          /usr/local/bin/warp-route-apply.sh \
          /usr/local/bin/warp-health-check.sh \
          /etc/systemd/system/warp-unlock.service \
          /etc/systemd/system/warp-health.service \
          /etc/systemd/system/warp-health.timer \
          /etc/wireguard/warp0.conf* \
          /etc/wireguard/warp-account.conf* \
          /etc/wireguard/warp.conf* \
          /etc/warp-unlock/wgcf-profile.conf \
          /tmp/auto_warp*.sh \
          /tmp/scan_us*.sh \
          /tmp/best_endpoint \
          /tmp/warp* 2>/dev/null || true

    systemctl daemon-reload 2>/dev/null || true
    # 彻底清理后立即重新同步网络环境参数
    detect_network_environment
    echo -e "${GREEN}✓ 深度清理完毕！系统网络与 DNS 已彻底恢复纯净原生状态。${NC}\n"
}

# ---------------------------------------------------------
# 功能 2：权威精准探测原生 IP 是否送中 (Google 官网底栏 + YouTube 深度双判)
# ---------------------------------------------------------
check_native_songzhong() {
    echo -e "${CYAN}[检测] 正在深度探测当前 VPS 原生 IP 的 Google / YouTube 真实归属...${NC}"

    local IFACE_ARG=""
    [ -n "$DEFAULT_IFACE" ] && IFACE_ARG="--interface $DEFAULT_IFACE"

    local CURRENT_IPV4 CURRENT_IPV6
    CURRENT_IPV4=$(curl -s -4 --max-time 3 $IFACE_ARG ip.sb 2>/dev/null || \
                   curl -s -4 --max-time 3 $IFACE_ARG ifconfig.me 2>/dev/null || \
                   curl -s -4 --max-time 3 $IFACE_ARG icanhazip.com 2>/dev/null)
    CURRENT_IPV6=$(curl -s -6 --max-time 4 $IFACE_ARG ip.sb 2>/dev/null || \
                   curl -s -6 --max-time 4 $IFACE_ARG ifconfig.me 2>/dev/null || \
                   curl -s -6 --max-time 4 $IFACE_ARG icanhazip.com 2>/dev/null)

    if [ -n "$CURRENT_IPV6" ]; then
        echo -e "当前原生 IPv6: ${YELLOW}${CURRENT_IPV6}${NC}"
    fi
    if [ -n "$CURRENT_IPV4" ]; then
        echo -e "当前原生 IPv4: ${YELLOW}${CURRENT_IPV4}${NC}"
    else
        echo -e "当前原生 IPv4: ${YELLOW}无 (单栈 IPv6 纯净环境)${NC}"
    fi

    local PROBE_OPT=""
    if [ $IS_V6_ONLY -eq 1 ]; then
        PROBE_OPT="-6"
    fi

    local IS_SONGZHONG=0
    local REASON=""
    local GOOGLE_GEO=""
    local YT_REGION=""

    # -------------------------------------------------------------
    # 核心探测 1：Google 首页前端配置与底栏归属判定
    # -------------------------------------------------------------
    echo -e "${CYAN}[检测] 正在访问 Google 搜索官网提取底层归属地区...${NC}"
    local GOOGLE_PAGE
    GOOGLE_PAGE=$(curl -sL $PROBE_OPT --max-time 8 $IFACE_ARG \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -H "Accept-Language: en-US,en" \
        "https://www.google.com" 2>/dev/null)

    GOOGLE_GEO=$(echo "$GOOGLE_PAGE" | grep -oP '\[1,null,null,\d+,\d+,"\K[A-Z]{3}' | head -n 1)
    [ -z "$GOOGLE_GEO" ] && GOOGLE_GEO=$(echo "$GOOGLE_PAGE" | grep -oP '2,1,200,"\K[A-Z]{3}' | head -n 1)

    local GOOGLE_HEADER
    GOOGLE_HEADER=$(curl -sI $PROBE_OPT --max-time 6 $IFACE_ARG "https://www.google.com" 2>/dev/null)
    local LOCATION
    LOCATION=$(echo "$GOOGLE_HEADER" | grep -i "^location:" | awk '{print $2}' | tr -d '\r')

    if [ "$GOOGLE_GEO" == "CHN" ] || [ "$GOOGLE_GEO" == "HKG" ]; then
        IS_SONGZHONG=1
        REASON="Google 搜索底层识别地区为中国/香港 ($GOOGLE_GEO)"
    elif echo "$LOCATION" | grep -qiE "google\.com\.hk|google\.cn"; then
        IS_SONGZHONG=1
        REASON="Google 搜索被强制重定向至 $LOCATION"
    elif echo "$GOOGLE_PAGE" | grep -qiE '"gl":"cn"|"gl":"hk"'; then
        IS_SONGZHONG=1
        REASON="Google 页面标注地区为中国 (gl: cn/hk)"
    fi

    # -------------------------------------------------------------
    # 核心探测 2：YouTube Premium 区域接口 (NodeQuality 行业标准)
    # -------------------------------------------------------------
    echo -e "${CYAN}[检测] 正在请求 YouTube 官方区域接口 (NodeQuality 同款)...${NC}"
    local YT_RES
    YT_RES=$(curl -sSL $PROBE_OPT --max-time 8 $IFACE_ARG \
        -H "Accept-Language: en" \
        -b "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai" \
        "https://www.youtube.com/premium" 2>&1)

    YT_REGION=$(echo "$YT_RES" | sed -n 's/.*"contentRegion":"\([^"]*\)".*/\1/p' | head -n 1)

    if echo "$YT_RES" | grep -q "www.google.cn"; then
        IS_SONGZHONG=1
        REASON="${REASON:-YouTube 源码引用 www.google.cn}"
    elif echo "$YT_RES" | grep -qiE '"countryCode":"CN"|"contentRegion":"CN"'; then
        IS_SONGZHONG=1
        REASON="${REASON:-YouTube 接口返回归属地为 [CN]}"
    fi

    # -------------------------------------------------------------
    # 输出探测汇总
    # -------------------------------------------------------------
    echo "--------------------------------------------------------"
    echo -e "Google 搜索定位国家: ${YELLOW}${GOOGLE_GEO:-未知}${NC}"
    echo -e "YouTube 接口返回地区: ${YELLOW}[${YT_REGION:-未知}]${NC}"
    if [ $IS_SONGZHONG -eq 1 ]; then
        echo -e "送中特征详情:        ${RED}$REASON${NC}"
        echo -e "综合归属判定:        ${RED}🔴 已确认送中 (部分或全部服务受限)${NC}"
        echo "--------------------------------------------------------"
        return 0
    else
        echo -e "综合归属判定:        ${GREEN}🟢 原生定位良好 (未送中)${NC}"
        echo "--------------------------------------------------------"
        return 1
    fi
}

# ---------------------------------------------------------
# 安装核心依赖
# ---------------------------------------------------------
install_dependencies() {
    echo -e "\n${CYAN}[1/4] 正在安装必要底层网络组件...${NC}"
    if command -v apt-get &>/dev/null; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y wireguard wireguard-tools ipset dnsmasq curl wget iptables jq e2fsprogs python3 >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y epel-release >/dev/null 2>&1
        dnf install -y wireguard-tools ipset dnsmasq curl wget iptables iptables-services jq e2fsprogs python3 >/dev/null 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y epel-release >/dev/null 2>&1
        yum install -y wireguard-tools ipset dnsmasq curl wget iptables iptables-services jq e2fsprogs python3 >/dev/null 2>&1
    fi
}

# ---------------------------------------------------------
# 原生 API 注册 Cloudflare WARP 节点配置 (完美支持单栈 IPv6 与双栈)
# ---------------------------------------------------------
setup_warp_profile() {
    [ -z "$WARP_ENDPOINTS" ] && detect_network_environment
    local TARGET_EP="${1:-${WARP_ENDPOINTS[0]}}"
    if [ $IS_V6_ONLY -eq 1 ] && [[ "$TARGET_EP" != *:* ]]; then
        TARGET_EP="${WARP_ENDPOINTS[0]}"
    fi
    echo -e "\n${CYAN}[2/4] 正在通过 Cloudflare 原生 API 生成 WARP 节点配置...${NC}"
    mkdir -p /etc/wireguard

    local PRIVKEY
    PRIVKEY=$(wg genkey 2>/dev/null || openssl rand -base64 32)
    local PUBKEY
    PUBKEY=$(echo "$PRIVKEY" | wg pubkey 2>/dev/null)

    # 生成全新随机设备指纹
    local INSTALL_ID FCM_TOKEN
    INSTALL_ID=$(head -c 16 /dev/urandom | base32 2>/dev/null | tr '[:upper:]' '[:lower:]' | head -c 22)
    [ -z "$INSTALL_ID" ] && INSTALL_ID=$(tr -dc 'a-z0-9' </dev/urandom | head -c 22)
    FCM_TOKEN="${INSTALL_ID}:APA91b$(head -c 96 /dev/urandom | base32 2>/dev/null | tr -d '\n=' | tr '[:upper:]' '[:lower:]' | head -c 134)"
    [ -z "$FCM_TOKEN" ] && FCM_TOKEN="${INSTALL_ID}:APA91b$(tr -dc 'a-z0-9' </dev/urandom | head -c 134)"

    local RESPONSE HTTP_STATUS CURL_STATUS API_ERROR
    RESPONSE=$(curl $CF_CURL_OPT -sS --connect-timeout 8 --max-time 20 -w '\n%{http_code}' -X POST -H 'User-Agent: okhttp/3.12.1' -H 'CF-Client-Version: a-6.3-2158' -H 'Content-Type: application/json' \
      -d "{\"key\":\"$PUBKEY\",\"install_id\":\"$INSTALL_ID\",\"fcm_token\":\"$FCM_TOKEN\",\"tos\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"model\":\"PC\",\"serial_number\":\"$INSTALL_ID\",\"locale\":\"en_US\"}" \
      https://api.cloudflareclient.com/v0a2158/reg)
    CURL_STATUS=$?
    HTTP_STATUS=${RESPONSE##*$'\n'}
    RESPONSE=${RESPONSE%$'\n'*}
    if [ "$CURL_STATUS" -ne 0 ] || [[ ! "$HTTP_STATUS" =~ ^2[0-9][0-9]$ ]]; then
        API_ERROR=$(jq -r '[.errors[]? | select(.code != null) | .code | tostring] | join(", ")' <<< "$RESPONSE" 2>/dev/null)
        echo -e "${RED}[错误] Cloudflare 注册请求失败 (curl: $CURL_STATUS，HTTP: ${HTTP_STATUS:-未知}，错误码: ${API_ERROR:-无})。${NC}"
        return 1
    fi

    local IPV4_ADDR="" IPV6_ADDR="" PEER_PUBKEY=""
    if command -v jq &>/dev/null; then
        IPV4_ADDR=$(jq -r '.config.interface.addresses.v4 // empty' <<< "$RESPONSE" 2>/dev/null)
        IPV6_ADDR=$(jq -r '.config.interface.addresses.v6 // empty' <<< "$RESPONSE" 2>/dev/null)
        PEER_PUBKEY=$(jq -r '.config.peers[0].public_key // empty' <<< "$RESPONSE" 2>/dev/null)
    fi
    if [ -z "$IPV4_ADDR" ] && command -v python3 &>/dev/null; then
        IPV4_ADDR=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('interface',{}).get('addresses',{}).get('v4',''))" <<< "$RESPONSE" 2>/dev/null)
    fi
    if [ -z "$IPV6_ADDR" ] && command -v python3 &>/dev/null; then
        IPV6_ADDR=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('interface',{}).get('addresses',{}).get('v6',''))" <<< "$RESPONSE" 2>/dev/null)
    fi
    if [ -z "$PEER_PUBKEY" ] && command -v python3 &>/dev/null; then
        PEER_PUBKEY=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('peers',[])[0].get('public_key',''))" <<< "$RESPONSE" 2>/dev/null)
    fi
    [ -z "$IPV4_ADDR" ] && IPV4_ADDR=$(echo "$RESPONSE" | grep -oP '"addresses"\s*:\s*\{[^}]*"v4"\s*:\s*"\K[0-9.]+' | head -n 1)
    [ -z "$IPV6_ADDR" ] && IPV6_ADDR=$(echo "$RESPONSE" | grep -oP '"addresses"\s*:\s*\{[^}]*"v6"\s*:\s*"\K[0-9a-fA-F:]+' | head -n 1)
    [ -z "$PEER_PUBKEY" ] && PEER_PUBKEY=$(echo "$RESPONSE" | grep -oP '"public_key"\s*:\s*"\K[^"]+' | head -n 1)

    if [ -z "$PRIVKEY" ] || [ -z "$PUBKEY" ] || [ -z "$IPV4_ADDR" ] || [ -z "$IPV6_ADDR" ] || [ -z "$PEER_PUBKEY" ]; then
        echo -e "${RED}[错误] WARP 注册失败或返回配置不完整，停止安装。${NC}"
        return 1
    fi

    # 尝试从 API 中自动提取 Cloudflare 推荐的 IPv6 端点 (并纠正 API 的 :0 占位端口)
    if [ $IS_V6_ONLY -eq 1 ]; then
        local CF_V6_EP=""
        if command -v jq &>/dev/null; then
            CF_V6_EP=$(jq -r '.config.peers[0].endpoint.v6 // empty' <<< "$RESPONSE" 2>/dev/null)
        fi
        if [ -z "$CF_V6_EP" ] && command -v python3 &>/dev/null; then
            CF_V6_EP=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('peers',[])[0].get('endpoint',{}).get('v6',''))" <<< "$RESPONSE" 2>/dev/null)
        fi
        [ -z "$CF_V6_EP" ] && CF_V6_EP=$(echo "$RESPONSE" | grep -oP '"endpoint"\s*:\s*\{[^}]*"v6"\s*:\s*"\K[^"]+' | head -n 1)

        if [ -n "$CF_V6_EP" ]; then
            # 剥离 API 返回的无效 :0 占位端口，强制绑定有效端口 2408
            CF_V6_EP=$(echo "$CF_V6_EP" | sed 's/:0$/:2408/')
            [[ "$CF_V6_EP" != *:* ]] && CF_V6_EP="[${CF_V6_EP}]:2408"
            TARGET_EP="$CF_V6_EP"
        fi
        if [[ "$TARGET_EP" != *:* ]]; then
            TARGET_EP="${WARP_ENDPOINTS[0]}"
        fi
    fi

    # 激活 Cloudflare WARP 官方账号授权 (warp_enabled: true)
    local DEV_ID
    DEV_ID=$(echo "$RESPONSE" | grep -oP '"id"\s*:\s*"\K[^"]+' | head -n 1)
    local TOKEN
    TOKEN=$(echo "$RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+' | head -n 1)

    if [ -n "$DEV_ID" ] && [ -n "$TOKEN" ]; then
        local PATCH_RES
        PATCH_RES=$(curl $CF_CURL_OPT -s -X PATCH -H 'User-Agent: okhttp/3.12.1' -H 'CF-Client-Version: a-6.3-2158' -H 'Content-Type: application/json' \
          -H "Authorization: Bearer $TOKEN" \
          -d '{"warp_enabled":true}' \
          "https://api.cloudflareclient.com/v0a2158/reg/$DEV_ID" 2>/dev/null)
        if echo "$PATCH_RES" | grep -q '"warp_enabled":\s*true'; then
            echo -e "${GREEN}✓ Cloudflare WARP 官方授权已成功激活 (warp_enabled: true)${NC}"
        fi

        ( umask 077; cat > /etc/wireguard/warp-account.conf << EOF
DEV_ID=$DEV_ID
TOKEN=$TOKEN
EOF
        )
        chmod 600 /etc/wireguard/warp-account.conf
    fi

    # 构建针对单栈 IPv6 与双栈自适应的 PostUp 规则
    local V6_ONLY_EXTRA_POSTUP=""
    # 默认路由由策略脚本管理；绝不让 WireGuard 的外层连接进入自身隧道。

    # IPv6 要求接口 MTU 至少 1280；过低会导致内核禁用接口 IPv6。
    ( umask 077; cat > /etc/wireguard/warp0.conf << EOF
[Interface]
PrivateKey = $PRIVKEY
Address = ${IPV4_ADDR}/32, ${IPV6_ADDR}/128
MTU = 1280
Table = off
FwMark = 51819
PostUp = ip rule add fwmark 51820 lookup 51820 priority 100 2>/dev/null || true; ip rule add oif warp0 lookup 51820 priority 90 2>/dev/null || true; ip rule add from 172.16.0.0/12 lookup 51820 priority 90 2>/dev/null || true; ip route replace default dev warp0 table 51820; ${V6_ONLY_EXTRA_POSTUP} iptables -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true; iptables -t nat -A POSTROUTING -o warp0 -j MASQUERADE; iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu; ip -6 rule add fwmark 51820 lookup 51820 priority 100 2>/dev/null || true; ip -6 rule add oif warp0 lookup 51820 priority 90 2>/dev/null || true; ip -6 rule add from ${IPV6_ADDR} lookup 51820 priority 90 2>/dev/null || true; ip -6 route replace default dev warp0 table 51820 2>/dev/null || true; ip6tables -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true; ip6tables -t nat -A POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true; ip6tables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = ip route del default dev warp0 table main 2>/dev/null || true; ip route flush table 51820 2>/dev/null || true; ip -6 route flush table 51820 2>/dev/null || true; ip rule del oif warp0 lookup 51820 2>/dev/null || true; ip rule del from 172.16.0.0/12 lookup 51820 2>/dev/null || true; ip rule del lookup 51820 priority 200 2>/dev/null || true; ip -6 rule del oif warp0 lookup 51820 2>/dev/null || true; ip -6 rule del from ${IPV6_ADDR} lookup 51820 2>/dev/null || true

[Peer]
PublicKey = ${PEER_PUBKEY:-bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=}
Endpoint = $TARGET_EP
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 10
EOF
    )
    chmod 600 /etc/wireguard/warp0.conf

    echo -e "${GREEN}✓ Cloudflare WARP 节点配置已生成 (Endpoint: $TARGET_EP)${NC}"
}

# ---------------------------------------------------------
# 配置 Dnsmasq 动态域名嗅探（双栈 DNS 兜底）
# ---------------------------------------------------------
setup_dnsmasq_rules() {
    echo -e "\n${CYAN}[3/4] 正在配置 Dnsmasq 动态域名拦截名单与防失效保护...${NC}"
    mkdir -p /etc/dnsmasq.d

    # 备份原生 resolv.conf
    [ ! -f /etc/resolv.conf.warp.bak ] && cp -f /etc/resolv.conf /etc/resolv.conf.warp.bak

    cat > /etc/dnsmasq.d/warp_unlock.conf << 'EOF'
server=2001:4860:4860::8888
server=2606:4700:4700::1111
server=8.8.8.8
server=1.1.1.1
cache-size=2000
no-resolv
clear-on-reload

# ----------------- 1. Google 搜索与核心基础服务 -----------------
ipset=/google.com/warp_unlock,warp_unlock6
ipset=/google.co.jp/warp_unlock,warp_unlock6
ipset=/google.com.hk/warp_unlock,warp_unlock6
ipset=/google.com.tw/warp_unlock,warp_unlock6
ipset=/google.cn/warp_unlock,warp_unlock6
ipset=/googleapis.com/warp_unlock,warp_unlock6
ipset=/googleusercontent.com/warp_unlock,warp_unlock6
ipset=/gstatic.com/warp_unlock,warp_unlock6
ipset=/1e100.net/warp_unlock,warp_unlock6
ipset=/google-analytics.com/warp_unlock,warp_unlock6
ipset=/googletagmanager.com/warp_unlock,warp_unlock6
ipset=/goo.gl/warp_unlock,warp_unlock6
ipset=/google.dev/warp_unlock,warp_unlock6
ipset=/web.dev/warp_unlock,warp_unlock6
ipset=/chrome.com/warp_unlock,warp_unlock6

# ----------------- 2. YouTube 全系列 (解决 YouTube 送中 / Premium 中国区限制) -----------------
ipset=/youtube.com/warp_unlock,warp_unlock6
ipset=/youtu.be/warp_unlock,warp_unlock6
ipset=/ytimg.com/warp_unlock,warp_unlock6
ipset=/googlevideo.com/warp_unlock,warp_unlock6
ipset=/yt.be/warp_unlock,warp_unlock6

# ----------------- 3. Google Play 商店 & 安卓生态核心 CDN -----------------
ipset=/android.com/warp_unlock,warp_unlock6
ipset=/googleplay.com/warp_unlock,warp_unlock6
ipset=/gvt1.com/warp_unlock,warp_unlock6
ipset=/gvt2.com/warp_unlock,warp_unlock6
ipset=/gvt3.com/warp_unlock,warp_unlock6
ipset=/ggpht.com/warp_unlock,warp_unlock6
ipset=/app-measurement.com/warp_unlock,warp_unlock6

# ----------------- 4. Google AI 全矩阵 (Gemini / Antigravity / AI Studio / NotebookLM) -----------------
ipset=/gemini.google.com/warp_unlock,warp_unlock6
ipset=/antigravity.google/warp_unlock,warp_unlock6
ipset=/aistudio.google.com/warp_unlock,warp_unlock6
ipset=/bard.google.com/warp_unlock,warp_unlock6
ipset=/deepmind.com/warp_unlock,warp_unlock6
ipset=/deepmind.google/warp_unlock,warp_unlock6
ipset=/notebooklm.google/warp_unlock,warp_unlock6
ipset=/generativeai.google/warp_unlock,warp_unlock6

# ----------------- 5. OpenAI / ChatGPT & Claude 全系列 -----------------
ipset=/openai.com/warp_unlock,warp_unlock6
ipset=/chatgpt.com/warp_unlock,warp_unlock6
ipset=/oaistatic.com/warp_unlock,warp_unlock6
ipset=/oaiusercontent.com/warp_unlock,warp_unlock6
ipset=/auth0.openai.com/warp_unlock,warp_unlock6
ipset=/claude.ai/warp_unlock,warp_unlock6
ipset=/anthropic.com/warp_unlock,warp_unlock6
EOF

    # 彻底停用 systemd-resolved 释放 53 端口，杜绝 Dnsmasq 启动失败
    if systemctl is-enabled systemd-resolved &>/dev/null || systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved 2>/dev/null || true
        systemctl disable systemd-resolved 2>/dev/null || true
    fi

    # 测试配置语法
    if ! dnsmasq --test 2>/dev/null; then
        echo -e "${YELLOW}[警告] Dnsmasq 配置存在不兼容语法，正在自动回退安全配置...${NC}"
        cat > /etc/dnsmasq.d/warp_unlock.conf << 'EOF'
server=2001:4860:4860::8888
server=2606:4700:4700::1111
server=8.8.8.8
server=1.1.1.1
cache-size=1000
ipset=/google.com/warp_unlock,warp_unlock6
ipset=/youtube.com/warp_unlock,warp_unlock6
ipset=/googlevideo.com/warp_unlock,warp_unlock6
ipset=/gemini.google.com/warp_unlock,warp_unlock6
ipset=/chatgpt.com/warp_unlock,warp_unlock6
EOF
    fi

    systemctl restart dnsmasq
    systemctl enable dnsmasq >/dev/null 2>&1

    if systemctl is-active --quiet dnsmasq; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
        rm -f /etc/resolv.conf
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null || true
        echo -e "${GREEN}✓ DNS 动态嗅探组件运行正常，并已锁定 /etc/resolv.conf 防止 DHCP 覆盖${NC}"
    else
        echo -e "${YELLOW}[保护] Dnsmasq 暂未成功监听，已自动配置双栈公共 DNS 确保网络绝对畅通！${NC}"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf << 'EOF'
nameserver 2001:4860:4860::8888
nameserver 2606:4700:4700::1111
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    fi
}

# ---------------------------------------------------------
# 配置系统级策略路由 (Ipset + Fwmark 双栈全覆盖)
# ---------------------------------------------------------
# 定时检测只读取状态并请求 trace，不因网络瞬断更换账号或修改路由。
setup_health_monitor() {
    cat > /usr/local/bin/warp-health-check.sh << 'EOF'
#!/bin/bash
set -u
family=both
policy=/etc/warp-unlock/exit-policy.conf
if [ -f "$policy" ]; then
    configured=$(sed -n 's/^family=//p' "$policy" | head -n 1)
    case "$configured" in ipv4|ipv6|both) family=$configured ;; *) echo '[错误] 出口协议配置无效'; exit 1 ;; esac
fi
if ! wg show warp0 >/dev/null 2>&1; then
    echo '[错误] 无法读取 warp0，WireGuard 接口不存在或不可用。'
    exit 1
fi
failed=0
for version in 4 6; do
    [ "$family" = ipv4 ] && [ "$version" = 6 ] && continue
    [ "$family" = ipv6 ] && [ "$version" = 4 ] && continue
    trace=$(curl -sS -"$version" --noproxy '*' --interface warp0 --connect-timeout 5 --max-time 10 https://www.cloudflare.com/cdn-cgi/trace 2>&1) || {
        echo "[错误] IPv${version} WARP 出口检测失败（网络、DNS 或超时）。"
        failed=1
        continue
    }
    ip=$(printf '%s\n' "$trace" | sed -n 's/^ip=//p' | head -n 1 | tr -d '\r')
    loc=$(printf '%s\n' "$trace" | sed -n 's/^loc=//p' | head -n 1 | tr -d '\r')
    warp=$(printf '%s\n' "$trace" | sed -n 's/^warp=//p' | head -n 1 | tr -d '\r')
    if { [ "$warp" != on ] && [ "$warp" != plus ]; } || [ -z "$ip" ]; then
        echo "[错误] IPv${version} 未验证到 WARP 出口（warp=${warp:-未知}）。"
        failed=1
    elif [ "$loc" = CN ] || [ "$loc" = RU ]; then
        echo "[警告] IPv${version} WARP 出口 $ip 的 Cloudflare 地区为 $loc。"
        failed=1
    else
        echo "[正常] IPv${version} WARP 出口 $ip，Cloudflare 地区 ${loc:-未知}。"
    fi
done
exit "$failed"
EOF
    chmod 755 /usr/local/bin/warp-health-check.sh
    cat > /etc/systemd/system/warp-health.service << 'EOF'
[Unit]
Description=WARP exit health check
After=network-online.target warp-unlock.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/warp-health-check.sh
EOF
    cat > /etc/systemd/system/warp-health.timer << 'EOF'
[Unit]
Description=Periodically check WARP exits

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
RandomizedDelaySec=30s
Unit=warp-health.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload || return 1
    if ! systemctl enable --now warp-health.timer; then
        echo -e "${RED}[错误] 无法启用 WARP 定时检测，请检查 systemd。${NC}"
        return 1
    fi
    echo -e "${GREEN}✓ WARP 定时检测已启用：约每 10 分钟一次。${NC}"
}

setup_routing_rules() {
    echo -e "\n${CYAN}[4/4] 正在配置系统底层动态路由与开机守护...${NC}"
    load_exit_policy
    if [ "$WARP_FAMILY" != ipv6 ]; then
        local warp_v4 conflicting_iface
        warp_v4=$(sed -n 's/^Address[[:space:]]*=[[:space:]]*\([^/, ]*\).*/\1/p' /etc/wireguard/warp0.conf | head -n 1)
        conflicting_iface=$(ip -4 -o addr show 2>/dev/null | awk -v addr="$warp_v4" '$2 != "warp0" && $4 ~ ("^" addr "/") {print $2; exit}')
        if [ -n "$warp_v4" ] && [ -n "$conflicting_iface" ]; then
            echo -e "${RED}[错误] $conflicting_iface 已使用 $warp_v4，可能拦截 warp0 的 IPv4 回包；请先处理现有隧道的地址冲突。${NC}"
            return 1
        fi
    fi
    apply_address_preference || return 1
    # 兼容旧配置：去掉旧版强制 IPv4 全局路由，加入隧道外层标记。
    sed -i 's/ip route replace default dev warp0 table main 2>\/dev\/null || true; ip rule add lookup 51820 priority 200 2>\/dev\/null || true;//' /etc/wireguard/warp0.conf
    sed -i 's/ip rule add from 172\.16\.0\.0\/12 lookup 51820 priority 90 2>\/dev\/null || true;//' /etc/wireguard/warp0.conf
    if grep -q '^FwMark[[:space:]]*=' /etc/wireguard/warp0.conf; then
        sed -i 's/^FwMark[[:space:]]*=.*/FwMark = 51819/' /etc/wireguard/warp0.conf
    else
        sed -i '/^Table = off/a FwMark = 51819' /etc/wireguard/warp0.conf
    fi

    cat > /usr/local/bin/warp-route-apply.sh << EOF
#!/bin/bash
# 0. 开启内核转发与优化反向路径过滤，解除 IPv6 禁用
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
# 开启转发前保留原本通过路由通告获取 IPv6 默认路由的接口。
for ra_file in /proc/sys/net/ipv6/conf/*/accept_ra; do
    [ -f "\$ra_file" ] || continue
    if [ "\$(cat "\$ra_file" 2>/dev/null)" = 1 ]; then
        ra_iface=\${ra_file%/accept_ra}; ra_iface=\${ra_iface##*/}
        sysctl -w "net.ipv6.conf.\$ra_iface.accept_ra=2" >/dev/null 2>&1 || true
    fi
done
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

# 1. 创建 ipset 集合 (IPv4 与 IPv6 双栈集合，86400秒超时)
ipset create warp_unlock hash:net timeout 86400 -exist
ipset create warp_unlock6 hash:net family inet6 timeout 86400 -exist

# 预置 Google 全球核心骨干网段 (双重保险，零延迟防遗漏)
for net in 142.250.0.0/15 172.217.0.0/16 216.58.192.0/19 173.194.0.0/16 74.125.0.0/16 64.233.160.0/19 66.102.0.0/20 66.249.64.0/19 108.177.0.0/17; do
    ipset add warp_unlock "\$net" -exist 2>/dev/null || true
done
for net6 in 2001:4860::/32 2607:f8b0::/32 2a00:1450::/32 2800:3f0::/32 2404:6800::/32; do
    ipset add warp_unlock6 "\$net6" -exist 2>/dev/null || true
done

# 2. 创建专用路由表 51820 (IPv4 & IPv6 双栈策略规则)
while ip rule del fwmark 51819 lookup main priority 80 2>/dev/null; do :; done
ip rule add fwmark 51819 lookup main priority 80
while ip -6 rule del fwmark 51819 lookup main priority 80 2>/dev/null; do :; done
ip -6 rule add fwmark 51819 lookup main priority 80
ip rule del fwmark 51820 lookup 51820 2>/dev/null || true
ip rule add fwmark 51820 lookup 51820 priority 100
ip rule del oif warp0 lookup 51820 2>/dev/null || true
ip rule add oif warp0 lookup 51820 priority 90 2>/dev/null || true
ip rule del from 172.16.0.0/12 lookup 51820 2>/dev/null || true

ip -6 rule del fwmark 51820 lookup 51820 2>/dev/null || true
ip -6 rule add fwmark 51820 lookup 51820 priority 100 2>/dev/null || true
ip -6 rule del oif warp0 lookup 51820 2>/dev/null || true
ip -6 rule add oif warp0 lookup 51820 priority 90 2>/dev/null || true

# 3. 启动 WireGuard 虚拟网卡
wg-quick down warp0 >/dev/null 2>&1 || true
if ! wg-quick up warp0; then
    echo "[错误] warp0 启动失败，请检查上方 wg-quick 错误。" >&2
    exit 1
fi

# 4. 确保 51820 路由表的默认网关为 warp0 虚拟接口 (双栈)
ip route flush table 51820 2>/dev/null || true
ip route replace default dev warp0 table 51820
ip -6 route flush table 51820 2>/dev/null || true
ip -6 route replace default dev warp0 table 51820 2>/dev/null || true

# 优先使用单独策略规则，外层 WireGuard 数据包带 51819 标记并走原生网络。
while ip rule del lookup 51820 priority 200 2>/dev/null; do :; done
while ip -6 rule del lookup 51820 priority 200 2>/dev/null; do :; done
while ip rule del priority 190 lookup main suppress_prefixlength 0 2>/dev/null; do :; done
while ip rule del priority 188 lookup main 2>/dev/null; do :; done
while ip -6 rule del priority 190 lookup main suppress_prefixlength 0 2>/dev/null; do :; done
while ip -6 rule del priority 188 lookup main 2>/dev/null; do :; done
ip route del default dev warp0 table main 2>/dev/null || true
if [ "$WARP_FAMILY" != ipv6 ] && { [ "$WARP_SCOPE" = global ] || [ "$IS_V6_ONLY" -eq 1 ]; }; then
    ip rule add priority 190 lookup main suppress_prefixlength 0
    native_v4=\$(ip -4 route get 1.1.1.1 mark 51819 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1)
    [ -n "\$native_v4" ] && [ "\$native_v4" != "\$(ip -4 -o addr show dev warp0 | awk '{print \$4}' | cut -d/ -f1 | head -n 1)" ] && ip rule add priority 188 from "\$native_v4/32" lookup main
    ip rule add not fwmark 51819 lookup 51820 priority 200
fi
if [ "$WARP_FAMILY" != ipv4 ] && [ "$WARP_SCOPE" = global ]; then
    ip -6 rule add priority 190 lookup main suppress_prefixlength 0
    # 已绑定原生 IPv6 地址的 SSH 等连接继续走原生路由。
    native_v6=\$(ip -6 route get 2606:4700:4700::1111 mark 51819 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1)
    [ -n "\$native_v6" ] && ip -6 rule add priority 188 from "\$native_v6/128" lookup main
    ip -6 rule add not fwmark 51819 lookup 51820 priority 200
fi

# 关闭全网卡 rp_filter 严格反向路径过滤
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1
[ -d /proc/sys/net/ipv4/conf/warp0 ] && sysctl -w net.ipv4.conf.warp0.rp_filter=0 >/dev/null 2>&1

# 5. 主动发包触发 WireGuard 握手建立 (双栈发包)
ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
ping6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1 || ping -6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1 || true
curl -s -m 2 --interface warp0 https://1.1.1.1 >/dev/null 2>&1 || true
curl -s -6 -m 2 --interface warp0 https://[2606:4700:4700::1111] >/dev/null 2>&1 || true

PEER_KEY=\$(wg show warp0 peers 2>/dev/null | head -n 1)
PEER_KEY=\${PEER_KEY:-bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=}

# 稳定等待接入点握手建立 (最多等 6 秒)
HANDSHAKE_OK=0
for s in \$(seq 1 6); do
    sleep 1
    RX=\$(wg show warp0 transfer 2>/dev/null | awk '{print \$2}')
    if [ -n "\$RX" ] && [ "\$RX" -gt 0 ]; then
        HANDSHAKE_OK=1
        break
    fi
done

# 若主节点未响应，平滑热切备用节点再次等待
if [ \$HANDSHAKE_OK -eq 0 ]; then
    for ep in ${WARP_ENDPOINTS[@]}; do
        wg set warp0 peer "\$PEER_KEY" endpoint "\$ep" 2>/dev/null || true
        ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
        ping -6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1 || true
        for s in \$(seq 1 3); do
            sleep 1
            RX=\$(wg show warp0 transfer 2>/dev/null | awk '{print \$2}')
            if [ -n "\$RX" ] && [ "\$RX" -gt 0 ]; then
                sed -i "s|Endpoint = .*|Endpoint = \$ep|" /etc/wireguard/warp0.conf
                HANDSHAKE_OK=1
                break 2
            fi
        done
    done
fi

# 5. iptables / ip6tables 标记匹配 ipset 的流量
iptables -t mangle -D OUTPUT -m set --match-set warp_unlock dst -j MARK --set-mark 51820 2>/dev/null || true
if [ "$WARP_FAMILY" != ipv6 ]; then
iptables -t mangle -A OUTPUT -m set --match-set warp_unlock dst -j MARK --set-mark 51820
fi
iptables -t mangle -D PREROUTING -m set --match-set warp_unlock dst -j MARK --set-mark 51820 2>/dev/null || true
if [ "$WARP_FAMILY" != ipv6 ]; then
iptables -t mangle -A PREROUTING -m set --match-set warp_unlock dst -j MARK --set-mark 51820
fi

ip6tables -t mangle -D OUTPUT -m set --match-set warp_unlock6 dst -j MARK --set-mark 51820 2>/dev/null || true
if [ "$WARP_FAMILY" != ipv4 ]; then
ip6tables -t mangle -A OUTPUT -m set --match-set warp_unlock6 dst -j MARK --set-mark 51820 2>/dev/null || true
fi
ip6tables -t mangle -D PREROUTING -m set --match-set warp_unlock6 dst -j MARK --set-mark 51820 2>/dev/null || true
if [ "$WARP_FAMILY" != ipv4 ]; then
ip6tables -t mangle -A PREROUTING -m set --match-set warp_unlock6 dst -j MARK --set-mark 51820 2>/dev/null || true
fi

# 6. TCP MSS 钳制 (解决 HTTPS / TLS Client Hello 大包导致 ERR_CONNECTION_CLOSED)
iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o warp0 -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# 7. NAT MASQUERADE (双栈源地址伪装)
iptables -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -o warp0 -j MASQUERADE
ip6tables -t nat -D POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true
ip6tables -t nat -A POSTROUTING -o warp0 -j MASQUERADE 2>/dev/null || true

# 8. 强制拦截 QUIC (UDP 443)，促使客户端回落至极速稳定的 TCP (TLS 1.3)
iptables -t filter -D FORWARD -p udp --dport 443 -m set --match-set warp_unlock dst -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
iptables -t filter -A FORWARD -p udp --dport 443 -m set --match-set warp_unlock dst -j REJECT --reject-with icmp-port-unreachable
iptables -t filter -D OUTPUT -p udp --dport 443 -m set --match-set warp_unlock dst -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
iptables -t filter -A OUTPUT -p udp --dport 443 -m set --match-set warp_unlock dst -j REJECT --reject-with icmp-port-unreachable

ip6tables -t filter -D FORWARD -p udp --dport 443 -m set --match-set warp_unlock6 dst -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
ip6tables -t filter -A FORWARD -p udp --dport 443 -m set --match-set warp_unlock6 dst -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
ip6tables -t filter -D OUTPUT -p udp --dport 443 -m set --match-set warp_unlock6 dst -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
ip6tables -t filter -A OUTPUT -p udp --dport 443 -m set --match-set warp_unlock6 dst -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
EOF
    chmod +x /usr/local/bin/warp-route-apply.sh
    /usr/local/bin/warp-route-apply.sh || return 1

    # 注册 systemd 开机自启
    cat > /etc/systemd/system/warp-unlock.service << 'EOF'
[Unit]
Description=WARP Dynamic Unlock Routing Service
After=network.target dnsmasq.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/warp-route-apply.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable warp-unlock.service >/dev/null 2>&1
    setup_health_monitor || return 1
}

# ---------------------------------------------------------
# 核心功能：全自动注销并获取新账号以真正更换出口 IP
# ---------------------------------------------------------
refresh_warp_ip() {
    echo -e "\n${CYAN}>>> 正在注册新的 WARP 账号并验证出口...${NC}"
    [ -z "$WARP_ENDPOINTS" ] && detect_network_environment

    local OLD_IP
    OLD_IP=$(curl -s -4 --interface warp0 --max-time 4 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "^ip=" | cut -d= -f2)
    [ -z "$OLD_IP" ] && OLD_IP=$(curl -s --interface warp0 --max-time 4 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "^ip=" | cut -d= -f2)
    [ -n "$OLD_IP" ] && echo -e "当前旧出口 IP: ${YELLOW}${OLD_IP}${NC}"

    # 保留旧账号，直到新注册已验证成功。
    local OLD_ID OLD_TOKEN
    if [ -f /etc/wireguard/warp-account.conf ]; then
        OLD_ID=$(awk -F= '/^DEV_ID=/{print $2}' /etc/wireguard/warp-account.conf 2>/dev/null)
        OLD_TOKEN=$(awk -F= '/^TOKEN=/{print $2}' /etc/wireguard/warp-account.conf 2>/dev/null)
    fi

    # 3. 生成全新私钥公钥
    local PRIVKEY PUBKEY
    PRIVKEY=$(wg genkey 2>/dev/null || openssl rand -base64 32)
    PUBKEY=$(echo "$PRIVKEY" | wg pubkey 2>/dev/null)

    # 4. 生成全新随机设备指纹
    local INSTALL_ID FCM_TOKEN
    INSTALL_ID=$(head -c 16 /dev/urandom | base32 2>/dev/null | tr '[:upper:]' '[:lower:]' | head -c 22)
    [ -z "$INSTALL_ID" ] && INSTALL_ID=$(tr -dc 'a-z0-9' </dev/urandom | head -c 22)
    FCM_TOKEN="${INSTALL_ID}:APA91b$(head -c 96 /dev/urandom | base32 2>/dev/null | tr -d '\n=' | tr '[:upper:]' '[:lower:]' | head -c 134)"
    [ -z "$FCM_TOKEN" ] && FCM_TOKEN="${INSTALL_ID}:APA91b$(tr -dc 'a-z0-9' </dev/urandom | head -c 134)"

    # 5. 请求 Cloudflare 注册全新账号
    local ep_idx=$(( RANDOM % ${#WARP_ENDPOINTS[@]} ))
    local TARGET_EP=${WARP_ENDPOINTS[$ep_idx]}
    if [ $IS_V6_ONLY -eq 1 ] && [[ "$TARGET_EP" != *:* ]]; then
        TARGET_EP="${WARP_ENDPOINTS[0]}"
    fi

    local REG_RES
    REG_RES=$(curl $CF_CURL_OPT -s -X POST -H 'User-Agent: okhttp/3.12.1' -H 'CF-Client-Version: a-6.3-2158' -H 'Content-Type: application/json' \
      -d "{\"key\":\"$PUBKEY\",\"install_id\":\"$INSTALL_ID\",\"fcm_token\":\"$FCM_TOKEN\",\"tos\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"model\":\"PC\",\"serial_number\":\"$INSTALL_ID\",\"locale\":\"en_US\"}" \
      https://api.cloudflareclient.com/v0a2158/reg 2>/dev/null)

    local NEW_DEV_ID NEW_TOKEN IPV4_ADDR IPV6_ADDR PEER_PUBKEY
    NEW_DEV_ID=$(echo "$REG_RES" | grep -oP '"id"\s*:\s*"\K[^"]+' | head -n 1)
    NEW_TOKEN=$(echo "$REG_RES" | grep -oP '"token"\s*:\s*"\K[^"]+' | head -n 1)

    if command -v jq &>/dev/null; then
        IPV4_ADDR=$(jq -r '.config.interface.addresses.v4 // empty' <<< "$REG_RES" 2>/dev/null)
        IPV6_ADDR=$(jq -r '.config.interface.addresses.v6 // empty' <<< "$REG_RES" 2>/dev/null)
        PEER_PUBKEY=$(jq -r '.config.peers[0].public_key // empty' <<< "$REG_RES" 2>/dev/null)
    fi
    if [ -z "$IPV4_ADDR" ] && command -v python3 &>/dev/null; then
        IPV4_ADDR=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('interface',{}).get('addresses',{}).get('v4',''))" <<< "$REG_RES" 2>/dev/null)
    fi
    if [ -z "$IPV6_ADDR" ] && command -v python3 &>/dev/null; then
        IPV6_ADDR=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('interface',{}).get('addresses',{}).get('v6',''))" <<< "$REG_RES" 2>/dev/null)
    fi
    if [ -z "$PEER_PUBKEY" ] && command -v python3 &>/dev/null; then
        PEER_PUBKEY=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('peers',[])[0].get('public_key',''))" <<< "$REG_RES" 2>/dev/null)
    fi
    [ -z "$IPV4_ADDR" ] && IPV4_ADDR=$(echo "$REG_RES" | grep -oP '"addresses"\s*:\s*\{[^}]*"v4"\s*:\s*"\K[0-9.]+' | head -n 1)
    [ -z "$IPV6_ADDR" ] && IPV6_ADDR=$(echo "$REG_RES" | grep -oP '"addresses"\s*:\s*\{[^}]*"v6"\s*:\s*"\K[0-9a-fA-F:]+' | head -n 1)
    [ -z "$PEER_PUBKEY" ] && PEER_PUBKEY=$(echo "$REG_RES" | grep -oP '"public_key"\s*:\s*"\K[^"]+' | head -n 1)

    if [ -z "$PRIVKEY" ] || [ -z "$PUBKEY" ] || [ -z "$NEW_DEV_ID" ] || [ -z "$NEW_TOKEN" ] || [ -z "$IPV4_ADDR" ] || [ -z "$IPV6_ADDR" ] || [ -z "$PEER_PUBKEY" ]; then
        echo -e "${RED}[错误] 新账号注册失败或配置不完整，保留原有账号和隧道。${NC}"
        return 1
    fi

    # 若为单栈 IPv6 则尝试获取动态推荐 IPv6 端点
    if [ $IS_V6_ONLY -eq 1 ]; then
        local CF_V6_EP=""
        if command -v jq &>/dev/null; then
            CF_V6_EP=$(jq -r '.config.peers[0].endpoint.v6 // empty' <<< "$REG_RES" 2>/dev/null)
        fi
        if [ -z "$CF_V6_EP" ] && command -v python3 &>/dev/null; then
            CF_V6_EP=$(python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('config',{}).get('peers',[])[0].get('endpoint',{}).get('v6',''))" <<< "$REG_RES" 2>/dev/null)
        fi
        [ -z "$CF_V6_EP" ] && CF_V6_EP=$(echo "$REG_RES" | grep -oP '"endpoint"\s*:\s*\{[^}]*"v6"\s*:\s*"\K[^"]+' | head -n 1)

        if [ -n "$CF_V6_EP" ]; then
            CF_V6_EP=$(echo "$CF_V6_EP" | sed 's/:0$/:2408/')
            [[ "$CF_V6_EP" != *:* ]] && CF_V6_EP="[${CF_V6_EP}]:2408"
            TARGET_EP="$CF_V6_EP"
        fi
        if [[ "$TARGET_EP" != *:* ]]; then
            TARGET_EP="${WARP_ENDPOINTS[0]}"
        fi
    fi

    # 6. 激活新账号授权
    if [ -n "$NEW_DEV_ID" ] && [ -n "$NEW_TOKEN" ]; then
        curl $CF_CURL_OPT -s -X PATCH -H 'User-Agent: okhttp/3.12.1' -H 'CF-Client-Version: a-6.3-2158' -H 'Content-Type: application/json' \
          -H "Authorization: Bearer $NEW_TOKEN" \
          -d '{"warp_enabled":true}' \
          "https://api.cloudflareclient.com/v0a2158/reg/$NEW_DEV_ID" >/dev/null 2>&1 || true

    fi

    # 7. 更新 /etc/wireguard/warp0.conf
    if ! cp /etc/wireguard/warp0.conf /etc/wireguard/warp0.conf.refresh.bak; then
        echo -e "${RED}[错误] 无法备份现有配置，停止刷新。${NC}"
        return 1
    fi
    wg-quick down warp0 >/dev/null 2>&1 || true
    sed -i "s|PrivateKey = .*|PrivateKey = $PRIVKEY|" /etc/wireguard/warp0.conf
    sed -i "s|Address = .*|Address = ${IPV4_ADDR}/32, ${IPV6_ADDR}/128|" /etc/wireguard/warp0.conf
    [ -n "$PEER_PUBKEY" ] && sed -i "s|PublicKey = .*|PublicKey = $PEER_PUBKEY|" /etc/wireguard/warp0.conf
    sed -i "s|Endpoint = .*|Endpoint = $TARGET_EP|" /etc/wireguard/warp0.conf
    sed -i "s|from [0-9a-fA-F:]\+ lookup 51820|from ${IPV6_ADDR} lookup 51820|g" /etc/wireguard/warp0.conf

    # 8. 重新拉起 WireGuard 接口并触发握手
    if ! wg-quick up warp0; then
        cp /etc/wireguard/warp0.conf.refresh.bak /etc/wireguard/warp0.conf
        wg-quick up warp0 || true
        echo -e "${RED}[错误] 新配置启动失败，已尝试恢复旧配置；旧账号尚未注销。${NC}"
        return 1
    fi
    if [ -x /usr/local/bin/warp-route-apply.sh ]; then
        /usr/local/bin/warp-route-apply.sh || return 1
    fi
    ( umask 077; cat > /etc/wireguard/warp-account.conf << EOF
DEV_ID=$NEW_DEV_ID
TOKEN=$NEW_TOKEN
EOF
    )
    chmod 600 /etc/wireguard/warp-account.conf
    ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
    ping -6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1 || true
    sleep 3

    # 9. 验收全新出口 IP 与地区归属 (优先通过 IPv4 trace)
    local NEW_TRACE NEW_IP NEW_LOC NEW_GLOC
    NEW_TRACE=$(curl -s -4 --interface warp0 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
    [ -z "$NEW_TRACE" ] && NEW_TRACE=$(curl -s --interface warp0 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
    NEW_IP=$(echo "$NEW_TRACE" | grep "^ip=" | cut -d= -f2)
    NEW_LOC=$(echo "$NEW_TRACE" | grep "^loc=" | cut -d= -f2)
    NEW_GLOC=$(curl -sL --interface warp0 --max-time 5 -H "Accept-Language: en-US,en" https://www.google.com 2>/dev/null | grep -oP '\[1,null,null,\d+,\d+,"\K[A-Z]{3}' | head -n 1)

    echo "--------------------------------------------------------"
    echo -e "刷新前旧出口 IP: ${YELLOW}${OLD_IP:-未知}${NC}"
    echo -e "刷新后新出口 IP: ${GREEN}${NEW_IP:-未知}${NC}"
    echo -e "新出口地区代码:  [${GREEN}${NEW_LOC:-未知}${NC}]"
    echo -e "Google 真实定位: [${GREEN}${NEW_GLOC:-未知}${NC}]"
    echo "--------------------------------------------------------"

    if [ -z "$NEW_IP" ] || ! grep -qx 'warp=on' <<< "$NEW_TRACE"; then
        echo -e "${RED}[错误] 新账号未验证到 WARP 出口；旧账号尚未注销，旧配置保存在 warp0.conf.refresh.bak。${NC}"
        return 1
    fi
    if [ -n "$OLD_ID" ] && [ -n "$OLD_TOKEN" ]; then
        curl $CF_CURL_OPT -s -m 4 -X DELETE -H "Authorization: Bearer $OLD_TOKEN" "https://api.cloudflareclient.com/v0a2158/reg/$OLD_ID" >/dev/null 2>&1 || true
    fi
    if [ "$NEW_IP" != "$OLD_IP" ]; then
        echo -e "${GREEN}✓ 出口 IP 刷新成功！已成功切换至全新公网出口！${NC}"
        return 0
    else
        echo -e "${YELLOW}账号已更换，但出口 IP 未发生变化。${NC}"
        return 0
    fi
}

# ---------------------------------------------------------
# 核心功能：全自动刷 IP 机制 (避开俄罗斯 RU 与中国 CN，锁定纯净区)
# ---------------------------------------------------------
ensure_clean_warp_region() {
    echo -e "\n${CYAN}正在验证 WARP 出口归属并自动避开俄罗斯(RU)/中国(CN)...${NC}"

    # 1. 确保 WireGuard 隧道底层握手已建立 (收到回包)
    local RX_BYTES
    RX_BYTES=$(wg show warp0 transfer 2>/dev/null | awk '{print $2}')
    if [ -z "$RX_BYTES" ] || [ "$RX_BYTES" -eq 0 ]; then
        echo -e "${YELLOW}[握手] 正在与 Cloudflare 全球 Anycast 节点建立 WireGuard 握手...${NC}"
        local PEER_KEY
        PEER_KEY=$(wg show warp0 peers 2>/dev/null | head -n 1)
        PEER_KEY=${PEER_KEY:-bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=}
        for ep in "${WARP_ENDPOINTS[@]}"; do
            wg set warp0 peer "$PEER_KEY" endpoint "$ep" 2>/dev/null || true
            ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
            ping -6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1 || true
            curl -s -m 2 --interface warp0 https://1.1.1.1 >/dev/null 2>&1 || true
            for _w in $(seq 1 3); do
                sleep 1
                RX_BYTES=$(wg show warp0 transfer 2>/dev/null | awk '{print $2}')
                if [ -n "$RX_BYTES" ] && [ "$RX_BYTES" -gt 0 ]; then
                    sed -i "s|Endpoint = .*|Endpoint = $ep|" /etc/wireguard/warp0.conf
                    echo -e "${GREEN}✓ WireGuard 隧道握手成功！(节点: $ep，已收到回包: ${RX_BYTES} 字节)${NC}"
                    break 2
                fi
            done
        done
        if [ -z "$RX_BYTES" ] || [ "$RX_BYTES" -eq 0 ]; then
            echo -e "${RED}[警告] WireGuard 握手未建立 (未收到 Cloudflare 响应)，请检查 VPS 的 UDP 端口/防火墙设置！${NC}"
            return 1
        fi
    fi

    local max_retries=6
    local retry_count=0

    while [ $retry_count -lt $max_retries ]; do
        sleep 2

        # 2. 获取 Cloudflare 官方权威 trace 信息与出口公网 IP (优先 IPv4，若无则自适应)
        local TRACE_INFO
        TRACE_INFO=$(curl -s -4 --interface warp0 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
        [ -z "$TRACE_INFO" ] && TRACE_INFO=$(curl -s --interface warp0 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
        local WARP_IP
        WARP_IP=$(echo "$TRACE_INFO" | grep "^ip=" | cut -d= -f2)
        local CF_LOC
        CF_LOC=$(echo "$TRACE_INFO" | grep "^loc=" | cut -d= -f2)

        # 3. 探测当前 WARP 出口的 YouTube 归属
        local YT_TEST
        YT_TEST=$(curl -sSL --interface warp0 --max-time 6 \
            -H "Accept-Language: en" \
            -b "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai" \
            "https://www.youtube.com/premium" 2>&1)
        local CUR_REGION
        CUR_REGION=$(echo "$YT_TEST" | sed -n 's/.*"contentRegion":"\([^"]*\)".*/\1/p' | head -n 1)

        # 4. 探测 Google 搜索底栏归属
        local GOOGLE_PAGE
        GOOGLE_PAGE=$(curl -sL --interface warp0 --max-time 6 -H "Accept-Language: en-US,en" "https://www.google.com" 2>/dev/null)
        local GOOGLE_LOC
        GOOGLE_LOC=$(echo "$GOOGLE_PAGE" | grep -oP '\[1,null,null,\d+,\d+,"\K[A-Z]{3}' | head -n 1)

        echo -e "[探测] 当前出口 IP: ${CYAN}${WARP_IP:-获取中}${NC} | Cloudflare地区: [${CF_LOC:-未知}] | YouTube地区: [${CUR_REGION:-未知}] | Google定位: [${GOOGLE_LOC:-未知}]"

        local IS_RESTRICTED=0
        if [ -z "$WARP_IP" ] || ! grep -qx 'warp=on' <<< "$TRACE_INFO"; then
            if [ $retry_count -lt 2 ]; then
                ((retry_count++))
                sleep 2
                continue
            fi
            echo -e "${RED}[错误] 无法验证 Cloudflare WARP 出口，停止刷新账号。请检查 DNS、路由和隧道。${NC}"
            return 1
        elif [ "$CF_LOC" == "RU" ] || [ "$CF_LOC" == "CN" ] || [ "$CUR_REGION" == "RU" ] || [ "$CUR_REGION" == "CN" ]; then
            IS_RESTRICTED=1
        fi

        if [ $IS_RESTRICTED -eq 1 ]; then
            ((retry_count++))
            echo -e "${YELLOW}[尝试 $retry_count/$max_retries] 当前出口为受限区，正在深度换新账号注销旧 IP...${NC}"
            refresh_warp_ip || return 1
            sleep 2
        else
            echo -e "${GREEN}✓ 已验证 WARP 出口 IP: ${WARP_IP} (地区: [${CF_LOC:-${CUR_REGION:-未知}}])${NC}"
            return 0
        fi
    done

    echo -e "${YELLOW}⚠ 已达自动重试上限，当前 WARP 出口 IP 为: ${WARP_IP:-未知} (地区: [${CF_LOC:-$CUR_REGION}])${NC}"
    return 1
}

# ---------------------------------------------------------
# 测试解锁状态
# ---------------------------------------------------------
test_unlock_status() {
    echo -e "\n${CYAN}正在预热 DNS 并验证全平台解锁效果...${NC}"

    # 主动触发 DNS 动态嗅探入库 (双栈嗅探)
    curl -sSL --max-time 6 "https://www.youtube.com/premium" >/dev/null 2>&1
    curl -sSL --max-time 6 "https://www.google.com" >/dev/null 2>&1
    curl -sSL --max-time 6 "https://chatgpt.com" >/dev/null 2>&1
    sleep 1

    # 0. 校验 WireGuard 隧道握手状态
    local RX_BYTES
    RX_BYTES=$(wg show warp0 transfer 2>/dev/null | awk '{print $2}')
    if [ -z "$RX_BYTES" ] || [ "$RX_BYTES" -eq 0 ]; then
        echo -e "${YELLOW}[注意] 正在与 Cloudflare 全球 Anycast 节点建立握手...${NC}"
        for _w in $(seq 1 6); do
            sleep 1
            RX_BYTES=$(wg show warp0 transfer 2>/dev/null | awk '{print $2}')
            if [ -n "$RX_BYTES" ] && [ "$RX_BYTES" -gt 0 ]; then
                echo -e "${GREEN}✓ WireGuard 隧道握手成功！(收到回包: ${RX_BYTES} 字节)${NC}"
                break
            fi
        done
    else
        echo -e "${GREEN}✓ WireGuard 隧道运行正常 (累计接收: ${RX_BYTES} 字节)${NC}"
    fi

    # 获取 WARP 虚拟接口出口 IP 信息 (双重兜底探测)
    local WARP_V4_EXIT WARP_V6_EXIT
    WARP_V4_EXIT=$(curl -s -4 --interface warp0 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "^ip=" | cut -d= -f2)
    [ -z "$WARP_V4_EXIT" ] && WARP_V4_EXIT=$(curl -s -4 --interface warp0 --max-time 5 https://api.ip.sb/ip 2>/dev/null | tr -d '\r\n ')
    [ -z "$WARP_V4_EXIT" ] && WARP_V4_EXIT=$(curl -s -4 --interface warp0 --max-time 5 https://ipinfo.io/ip 2>/dev/null | tr -d '\r\n ')

    WARP_V6_EXIT=$(curl -s -6 --interface warp0 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "^ip=" | cut -d= -f2)
    [ -z "$WARP_V6_EXIT" ] && WARP_V6_EXIT=$(curl -s -6 --interface warp0 --max-time 5 https://api64.ipify.org 2>/dev/null | tr -d '\r\n ')

    # 1. 验证 YouTube 解锁
    local YT_TEST
    YT_TEST=$(curl -sSL --interface warp0 --max-time 8 \
        -H "Accept-Language: en" \
        -b "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai" \
        "https://www.youtube.com/premium" 2>&1)
    local YT_REG
    YT_REG=$(echo "$YT_TEST" | sed -n 's/.*"contentRegion":"\([^"]*\)".*/\1/p' | head -n 1)

    # 2. 验证 Google 搜索
    local GOOGLE_CODE
    GOOGLE_CODE=$(curl -sI -o /dev/null -w "%{http_code}" -L --interface warp0 --max-time 8 https://www.google.com/ncr)

    # 3. 验证 Gemini / Antigravity
    local GEMINI_RES GEMINI_OK=unknown
    GEMINI_RES=$(curl -fsSL --interface warp0 --max-time 8 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -H "Accept-Language: en-US,en" https://gemini.google.com 2>/dev/null) || GEMINI_RES=""
    if echo "$GEMINI_RES" | grep -qiE "not supported in your country|country_unavailable|not available in your region"; then
        GEMINI_OK=0
    fi

    # 4. 验证 OpenAI / ChatGPT
    local CHATGPT_CODE
    CHATGPT_CODE=$(curl -sI -o /dev/null -w "%{http_code}" -L --interface warp0 --max-time 8 https://chatgpt.com 2>/dev/null)

    echo "========================================================"
    echo -e "               🎉 解锁与脱离送中验证报告                 "
    echo "========================================================"
    echo -e "WARP 出口 IPv4:              ${GREEN}${WARP_V4_EXIT:-获取中}${NC}"
    echo -e "WARP 出口 IPv6:              ${GREEN}${WARP_V6_EXIT:-获取中}${NC}"

    if [ "$YT_REG" == "RU" ]; then
        echo -e "YouTube Premium 归属:        ${YELLOW}⚠ 归属俄罗斯 [RU] (免广告但 Gemini 不支持，建议选菜单 5 刷新)${NC}"
    elif echo "$YT_TEST" | grep -q "www.google.cn"; then
        echo -e "YouTube Premium 解锁:        ${RED}✗ 仍显示送中 (请检查 WARP 运行状态)${NC}"
    elif [ -n "$YT_REG" ] && [ "$YT_REG" != "CN" ]; then
        echo -e "YouTube Premium 归属:        ${GREEN}[$YT_REG] (仍需实际验证服务)${NC}"
    else
        echo -e "YouTube Premium 归属:        ${YELLOW}未知或受限 [${YT_REG:-未知}]${NC}"
    fi

    if [ "$GOOGLE_CODE" == "200" ]; then
        echo -e "Google 搜索访问:             ${GREEN}HTTP $GOOGLE_CODE (地区需另行验证)${NC}"
    else
        echo -e "Google 搜索/API 解锁:        ${YELLOW}⚠ 状态码: $GOOGLE_CODE (200/302均属正常)${NC}"
    fi

    if [ "$GEMINI_OK" = 0 ]; then
        echo -e "Google Gemini / Antigravity: ${RED}✗ 当前地区受限 (不可用，建议选菜单 5 刷新)${NC}"
    else
        echo -e "Google Gemini / Antigravity: ${YELLOW}未验证 (网页响应不能证明账号可用)${NC}"
    fi

    if [ "$CHATGPT_CODE" == "200" ] || [ "$CHATGPT_CODE" == "302" ]; then
        echo -e "OpenAI / ChatGPT 网页响应:   ${GREEN}HTTP $CHATGPT_CODE (账号功能需另行验证)${NC}"
    else
        echo -e "OpenAI / ChatGPT 访问状态:   ${YELLOW}⚠ 状态码: $CHATGPT_CODE${NC}"
    fi
    echo "========================================================"
    if [ -z "$WARP_V4_EXIT" ] && [ -z "$WARP_V6_EXIT" ]; then
        echo -e "${RED}WARP 出口未验证，请检查 wg show warp0、IPv6 路由和 DNS。${NC}\n"
        return 1
    fi
}

# ---------------------------------------------------------
# 智能执行主流程
# ---------------------------------------------------------
smart_install_flow() {
    auto_clean_old_warp

    if check_native_songzhong; then
        echo -e "\n${YELLOW}>>> 检测到原生 IP 已送中，全自动启动 WARP 动态分流解锁流程...${NC}"
        select_exit_policy || return 1
        install_dependencies
        setup_warp_profile || return 1
        setup_dnsmasq_rules
        setup_routing_rules || return 1
        ensure_clean_warp_region || return 1
        test_unlock_status
    else
        echo -e "\n${GREEN}======================================================${NC}"
        echo -e "${GREEN}提示：原生 IP 基础定位未触发硬性跳转。${NC}"
        echo -e "${YELLOW}但若您在浏览器访问 Google 仍未显示美国、或打不开 Gemini，强烈建议继续安装！${NC}"
        echo -e "${GREEN}======================================================${NC}"
        read -p "是否继续安装 WARP 动态分流？[Y/n] (默认直接按回车继续安装): " force_choice
        force_choice=${force_choice:-y}
        case "$force_choice" in
            [yY][eE][sS]|[yY])
                echo -e "\n${YELLOW}>>> 开始安装 WARP 动态分流解锁...${NC}"
                select_exit_policy || return 1
                install_dependencies
                setup_warp_profile || return 1
                setup_dnsmasq_rules
                setup_routing_rules || return 1
                ensure_clean_warp_region || return 1
                test_unlock_status
                ;;
            *)
                echo -e "\n已取消安装，保持原生网络状态。\n"
                ;;
        esac
    fi
}

# ---------------------------------------------------------
# 主菜单
# ---------------------------------------------------------
clear
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║      🚀 VPS 系统级 WARP 智能动态解锁脚本 (单栈V6深度适配版)  ║"
echo "║   • 纯IPv6适配：原生支持单栈 IPv6 VPS，自动赋能 IPv4 出口   ║"
echo "║   • 启动自检：自动彻底清理老版本脚本及旧规则残留          ║"
echo "║   • 智能判断：原生送中才安装，未送中则自动免装/可自选     ║"
echo "║   • 避俄防送：智能刷 IP，自动规避俄罗斯/中国等受限地区    ║"
echo "║   • 动态嗅探：Google全家桶/YouTube/Gemini/Antigravity/AI   ║"
echo "║   • 防覆写：锁定 DNS 属性，彻底防止重启或 DHCP 导致失效   ║"
echo "║   • 零配置：小白直接运行，各代理节点无需任何路由改动       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ $IS_V6_ONLY -eq 1 ]; then
    echo -e "当前网络环境: ${GREEN}单栈 IPv6 纯净环境 (IPv6-Only VPS)${NC}"
else
    echo -e "当前网络环境: ${GREEN}双栈 / IPv4 环境${NC}"
fi
echo ""

echo "1. 智能运行 (自动清理旧版 + 精准检测送中 + 智能安装)"
echo "2. 强制安装 / 修复 WARP 动态解锁"
echo "3. 测试当前解锁与归属状态"
echo "4. 彻底卸载恢复原生网络"
echo "5. 智能刷新 WARP 出口 IP (自动避开俄罗斯/中国，刷美区)"
echo "6. 修改 WARP 出口协议、范围与地址优先级"
echo "7. 为现有 WARP 安装定时健康检查"
echo "0. 退出"
echo ""
read -p "请输入选项 [0-7] (默认按回车直接智能运行 [1]): " choice
choice=${choice:-1}

case $choice in
    1)
        smart_install_flow
        ;;
    2)
        auto_clean_old_warp
        detect_network_environment
        select_exit_policy || exit 1
        install_dependencies
        setup_warp_profile || exit 1
        setup_dnsmasq_rules
        setup_routing_rules || exit 1
        ensure_clean_warp_region || exit 1
        test_unlock_status
        ;;
    3)
        check_native_songzhong
        test_unlock_status
        ;;
    4)
        auto_clean_old_warp
        ADDRESS_PREFERENCE=default
        apply_address_preference || exit 1
        rm -f "$WARP_POLICY_FILE"
        echo -e "${GREEN}✓ 已彻底卸载并恢复原生网络配置。${NC}"
        ;;
    5)
        detect_network_environment
        refresh_warp_ip || exit 1
        ensure_clean_warp_region || exit 1
        test_unlock_status
        ;;
    6)
        if [ ! -f /etc/wireguard/warp0.conf ]; then
            echo '请先安装 WARP。'
            exit 1
        fi
        select_exit_policy || exit 1
        setup_routing_rules || exit 1
        echo '出口设置已更新。'
        ;;
    7)
        if [ ! -f /etc/wireguard/warp0.conf ]; then
            echo '请先安装 WARP。'
            exit 1
        fi
        setup_health_monitor || exit 1
        ;;
    *)
        exit 0
        ;;
esac
