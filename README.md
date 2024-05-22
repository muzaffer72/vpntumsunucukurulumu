SCRIPT INSTALLER

##### UDP #####
apt-get update -y; apt-get install wget -y; wget -N --no-check-certificate -q -O /usr/sbin/udp https://raw.githubusercontent.com/TeamPogi/relly/main/udp-script.sh && chmod +x /usr/sbin/udp && bash /usr/sbin/udp >/dev/null 2>&1

##### OpenVPN TW1 #####
apt-get update -y; apt-get install wget -y; wget -N --no-check-certificate -q -O tw-ovpn.sh https://raw.githubusercontent.com/TeamPogi/relly/main/tw-ovpn.sh && chmod +x tw-ovpn.sh && bash tw-ovpn.sh >/dev/null 2>&1

##### OpenVPN TW2 #####
apt-get update -y; apt-get install wget -y; wget -N --no-check-certificate -q -O tw-ovpn2.sh https://raw.githubusercontent.com/TeamPogi/relly/main/tw-ovpn2.sh && chmod +x tw-ovpn2.sh && bash tw-ovpn2.sh >/dev/null 2>&1

##### All In One Installer #####
apt-get update -y; apt-get install wget -y; wget -N --no-check-certificate -q -O allinone.installer https://raw.githubusercontent.com/TeamPogi/relly/main/allinone.installer && chmod +x allinone.installer && bash allinone.installer >/dev/null 2>&1

##### Slow DNS #####
apt-get update -y;  wget -N --no-check-certificate -q -O cRizWorKz-TW.sh https://raw.githubusercontent.com/TeamPogi/relly/main/cRizWorKz-TW.sh && chmod +x cRizWorKz-TW.sh && bash cRizWorKz-TW.sh >/dev/null 2>&1
