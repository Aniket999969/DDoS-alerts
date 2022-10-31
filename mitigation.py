import os, sys, socket, requests, time, subprocess, shlex, json, psutil
from datetime import datetime, date
from discord_webhook import DiscordWebhook, DiscordEmbed
from requests import get
from requests.api import request

def Clear():
    os.system('clear')

date55 = subprocess.getoutput(r"date +'%B the %dth, %Y'")
timenow = datetime.now()
timenow2 = timenow.strftime("%d-%m-%Y-%H:%M:%S")
content = requests.get('https://pastebin.com/raw/iyRSLn9L').text
ethernet = "eno1"
ip = subprocess.getoutput(r"ip -4 addr show eno1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' ")
highestpkts = 5000
txts = "/root/tcpdump"
txtout="capture.{}.txt".format(timenow.strftime("%d-%m-%Y-%H:%M:%S"))
with open('config.json') as f:
    config = json.load(f)
titlethingy = config.get('title')
description22 = config.get('description')
url22 = config.get('url')
imagev11 = config.get('image')
footerv3 = config.get('footer')
colorv3 = config.get('color')
webhook_url = config.get('webhook')



ascii = """
[38;2;250;157;248m▪[38;2;236;163;248m [38;2;222;170;248m [38;2;208;176;249m▐[38;2;193;183;249m▄[38;2;179;189;250m•[38;2;165;196;250m [38;2;151;202;251m▄[38;2;136;209;251m [38;2;122;215;252m [38;2;108;222;252m▄[38;2;94;228;253m·[38;2;79;235;253m [38;2;65;241;254m▄[38;2;51;248;254m▌
[38;2;250;157;248m█[38;2;236;163;248m█[38;2;222;170;248m [38;2;208;176;249m [38;2;193;183;249m█[38;2;179;189;250m▌[38;2;165;196;250m█[38;2;151;202;251m▌[38;2;136;209;251m▪[38;2;122;215;252m▐[38;2;108;222;252m█[38;2;94;228;253m▪[38;2;79;235;253m█[38;2;65;241;254m█[38;2;51;248;254m▌
[38;2;250;157;248m▐[38;2;236;163;248m█[38;2;222;170;248m·[38;2;208;176;249m [38;2;193;183;249m·[38;2;179;189;250m█[38;2;165;196;250m█[38;2;151;202;251m·[38;2;136;209;251m [38;2;122;215;252m▐[38;2;108;222;252m█[38;2;94;228;253m▌[38;2;79;235;253m▐[38;2;65;241;254m█[38;2;51;248;254m▪
[38;2;250;157;248m▐[38;2;236;163;248m█[38;2;222;170;248m▌[38;2;208;176;249m▪[38;2;193;183;249m▐[38;2;179;189;250m█[38;2;165;196;250m·[38;2;151;202;251m█[38;2;136;209;251m▌[38;2;122;215;252m [38;2;108;222;252m▐[38;2;94;228;253m█[38;2;79;235;253m▀[38;2;65;241;254m·[38;2;51;248;254m.
[38;2;250;157;248m▀[38;2;236;163;248m▀[38;2;222;170;248m▀[38;2;208;176;249m•[38;2;193;183;249m▀[38;2;179;189;250m▀[38;2;165;196;250m [38;2;151;202;251m▀[38;2;136;209;251m▀[38;2;122;215;252m [38;2;108;222;252m [38;2;94;228;253m▀[38;2;79;235;253m [38;2;65;241;254m•[38;2;51;248;254m 
"""

ddosbanner = """[38;2;255;5;5mW[38;2;255;7;5me[38;2;255;9;5m [38;2;255;12;5mh[38;2;255;14;5ma[38;2;255;16;5mv[38;2;255;19;5me[38;2;255;21;5m [38;2;255;24;5md[38;2;255;26;5me[38;2;255;28;5mt[38;2;255;31;5me[38;2;255;33;5mc[38;2;255;35;5mt[38;2;255;38;5me[38;2;255;40;5md[38;2;255;43;5m [38;2;255;45;5ma[38;2;255;47;5m [38;2;255;50;5mD[38;2;255;52;5m([38;2;255;54;5mD[38;2;255;57;5mo[38;2;255;59;5ms[38;2;255;62;5m)[38;2;255;64;5m [38;2;255;66;5ma[38;2;255;69;5mt[38;2;255;71;5mt[38;2;255;73;5ma[38;2;255;76;5mc[38;2;255;78;5mk[38;2;255;81;5m [38;2;255;83;5ms[38;2;255;85;5me[38;2;255;88;5mn[38;2;255;90;5md[38;2;255;92;5mi[38;2;255;95;5mn[38;2;255;97;5mg[38;2;255;100;5m [38;2;255;102;5mn[38;2;255;104;5mo[38;2;255;107;5mt[38;2;255;109;5mi[38;2;255;111;5mf[38;2;255;114;5mi[38;2;255;116;5mc[38;2;255;119;5ma[38;2;255;121;5mt[38;2;255;123;5mi[38;2;255;126;5mo[38;2;255;128;5mn[38;2;255;130;5m.[38;2;255;133;5m.[38;2;255;135;5m."""
ddosbanner2 = """[38;2;255;5;5ma[38;2;255;5;5mt[38;2;254;6;5mt[38;2;253;7;5ma[38;2;252;8;5mc[38;2;252;9;5mk[38;2;251;10;5m [38;2;250;11;5mn[38;2;249;11;5mo[38;2;249;12;5mt[38;2;248;13;5mi[38;2;247;14;4mf[38;2;246;15;4mi[38;2;246;16;4mc[38;2;245;17;4ma[38;2;244;17;4mt[38;2;243;18;4mi[38;2;243;19;4mo[38;2;242;20;4mn[38;2;241;21;4m [38;2;240;22;4ms[38;2;240;23;3me[38;2;239;24;3mn[38;2;238;24;3mt[38;2;237;25;3m [38;2;237;26;3ms[38;2;236;27;3mu[38;2;235;28;3mc[38;2;234;29;3mc[38;2;234;30;3me[38;2;233;30;3ms[38;2;232;31;3ms[38;2;231;32;2mf[38;2;231;33;2mu[38;2;230;34;2ml[38;2;229;35;2ml[38;2;228;36;2my[38;2;228;37;2m [38;2;227;37;2mc[38;2;226;38;2mh[38;2;225;39;2me[38;2;225;40;2mc[38;2;224;41;1mk[38;2;223;42;1m [38;2;222;43;1md[38;2;222;43;1mi[38;2;221;44;1ms[38;2;220;45;1mc[38;2;219;46;1mo[38;2;219;47;1mr[38;2;218;48;1md[38;2;217;49;1m!"""
waitimev2 = """[38;2;255;255;36mW[38;2;253;248;34ma[38;2;250;241;32mi[38;2;248;234;30mt[38;2;245;226;27mi[38;2;243;219;25mn[38;2;240;212;23mg[38;2;238;205;21m [38;2;235;197;18m6[38;2;232;190;16m0[38;2;230;183;14m [38;2;227;176;12ms[38;2;225;168;9me[38;2;222;161;7mc[38;2;220;154;5mo[38;2;217;147;3mn[38;2;214;139;0md[38;2;214;134;3ms[38;2;213;128;6m [38;2;212;123;9mt[38;2;211;117;12mo[38;2;210;112;15m [38;2;209;106;19mp[38;2;208;101;22mu[38;2;207;95;25mt[38;2;206;90;28m [38;2;205;84;31mI[38;2;204;79;35mX[38;2;203;73;38mY[38;2;202;68;41m [38;2;201;62;44mv[38;2;200;57;47m2[38;2;199;51;51m [38;2;197;51;63mo[38;2;195;50;76mu[38;2;192;49;89mt[38;2;190;48;102m [38;2;187;47;114mo[38;2;185;46;127mf[38;2;182;45;140m [38;2;180;44;153mm[38;2;178;43;165mi[38;2;175;42;178mt[38;2;173;41;191mi[38;2;170;40;204mg[38;2;168;39;216ma[38;2;165;38;229mt[38;2;163;37;242mion"""

while(True):
    old_b = subprocess.check_output("grep %s /proc/net/dev | cut -d : -f2 | awk \'{print $1}\'" % ethernet, shell=True)
    old_ps = subprocess.check_output("grep %s /proc/net/dev | cut -d : -f2 | awk \'{print $2}\'" % ethernet, shell=True)
    old_b2 = int(float(old_b.decode('utf8').rstrip()))
    old_ps2 = int(float(old_ps.decode('utf8').rstrip()))
    time.sleep(1)
    new_b = subprocess.check_output("grep %s /proc/net/dev | cut -d : -f2 | awk \'{print $1}\'" % ethernet, shell=True)
    new_ps = subprocess.check_output('grep %s /proc/net/dev | cut -d : -f2 | awk \'{print $2}\'' % ethernet, shell=True)
    new_ps2 = int(float(new_ps.decode('utf8').rstrip()))
    new_b2 = int(float(new_b.decode('utf8').rstrip()))
    pps = (new_ps2 - old_ps2)
    byte = (new_b2 - old_b2)
    Clear()
    gigs = (byte/1024 ** 3)
    mbps = byte / 125000
    kbps = (byte/1024 ** 1)
    cores = psutil.cpu_count() 
    frequency = psutil.cpu_freq().current
    os22 = subprocess.getoutput(r"egrep '^(NAME)=' /etc/os-release") 
    ram=subprocess.getoutput(r" free -m | awk 'NR==2{printf  $3*100/$2 }' ")
    ips= subprocess.getoutput(r"netstat -ntu | grep -v LISTEN | awk '{print $5}' | wc -l")
    CPU=subprocess.getoutput(r"top -n 1 -b | awk '/^%Cpu/{print $2}' ")
    ip=subprocess.getoutput(r"ip -4 addr show eno1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' ")
    lastthingy434 = subprocess.getoutput(r"ls /root/tcpdump/report/nodupes/ | tail -n 1")
    upt=subprocess.getoutput(f" uptime -p ")
    now = subprocess.getoutput(r"date +'%H:%M:%S   %B the %dth, %Y'")
    iptr =subprocess.getoutput(r"iptables-save | wc -l")
    test1 = subprocess.getoutput(r"cat /sys/class/net/eno1/statistics/rx_dropped")
    tf543 = subprocess.getoutput(r"cat /root/tcpdump/flags/test3.txt | head -2 | awk 'NR > 1 { print }'")
    latype = subprocess.getoutput(r"cat /root/tcpdump/attacktype/attacktype.txt")
    lastspoof22 = subprocess.getoutput(r"cat /root/tcpdump/spoofing/spoofing.txt")
    moip=subprocess.getoutput(r"cat /root/tcpdump/report/nodupes/{} | uniq | head -1".format(lastthingy434))
    sp1212=subprocess.getoutput(r" cat /root/tcpdump/src/test2.txt | head -2 | awk 'NR > 1 { print }'")
    ap=subprocess.getoutput(r"cat /root/tcpdump/dst/test.txt | head -2 | awk 'NR > 1 { print }'")
    nocap = subprocess.getoutput(r"ls /root/tcpdump/pcap/ | wc -l")
    lpc = subprocess.getoutput(r"ls /root/tcpdump/pcap/ | wc -l")
    startTime = time.time()
    executionTime = round(time.time() - time.time(), 20)
    if int(pps) > 2500:
        load = "High"
    if int(pps) > 1000 < 2000:
        load = "Medium"
    if int(pps) > 500 < 1000:
        load = "low"
    if int(pps) > 0 < 2500:
        load = "essentially no load"
    print(f"{ascii}")
    print(f"╔═════════════════════════════════════════════════════════════════════════════╗")    
    print(f"   List Info:                                                                 ")    
    print(f"   Ip address: {ip}                                                           ")    
    print(f"   Cpu percent: {CPU} %                                                       ")  
    print(f"   Packets Per Second: {pps}                                                  ")
    print(f"   Server load: {load}                                                        ")    
    print(f"   Unique Ips: {ips}                                                          ")
    print(f"   Last Most Occured IP: {moip}                                               ")
    print(f"   Cpu cores: {cores}                                                         ")
    print(f"   Ram usage: {ram} %                                                         ")
    print(f"   Last attacked port: {ap}                                                   ")    
    print(f"   Last attacked src port: {sp1212}                                           ") 
    print(f"   Cpu freq: {frequency}                                                      ")
    print(f"   Last Pcap {lpc}                                                            ")
    print(f"   Pcap # {nocap}                                                             ")
    print(f"   Server Uptime: {upt}                                                       ")
    print(f"   Mb/s: {mbps}                                                               ")
    print(f"   OS: {os22}                                                                 ")
    print(f"   Current Time: {now}                                                        ")
    print(f"   Iptable rules: {iptr}                                                      ")
    print(f"   FW blocked {test1} bytes                                                   ")
    print(f"   Attack-Type: {latype}                                                      ")
    print(f"   Last Attack-Flag: {tf543}                                                  ")
    print(f"   Spoof? (last attack): {lastspoof22}                                        ")
    print(f"   Script took {executionTime} seconds to refresh                             ")
    print(f"   Mitigation | Compiled by Silly | User:IDK? | ID: 69420                     ")
    print(f"╚═════════════════════════════════════════════════════════════════════════════╝")    
    time.sleep(1.5)
    if(pps > highestpkts):
        timenow2 = timenow.strftime("%d-%m-%Y-%H:%M:%S")
        os.system('clear')
        os.system("tcpdump -n -s0 -c 5000 -w {}/pcap/capture.{}.pcap".format(txts, timenow2))
        os.system('clear')
        os.system("tshark -r {}/pcap/capture.{}.pcap -T fields -e ip.src > {}/report/report.{}.txt".format(txts, timenow2, txts, timenow2))
        os.system('clear')
        os.system("sort {}/report/report.{}.txt | uniq > {}/report/nodupes/report-nodup.{}.txt".format(txts, timenow2, txts, timenow2))
        os.system('clear')
        os.system("tshark -r {}/pcap/capture.{}.pcap -T fields -E header=y -e ip.proto -e tcp.flags -e udp.srcport -e tcp.srcport -e data > {}/ramdom/{}.txt".format(txts, timenow2, txts, timenow2))
        os.system('clear')
        os.system("tshark -r {}/pcap/capture.{}.pcap -T fields -E header=y -e tcp.dstport > {}/dst/test.txt".format(txts, timenow2, txts))
        os.system('clear')
        os.system("tshark -r {}/pcap/capture.{}.pcap -T fields -E header=y -e tcp.srcport > {}/src/test2.txt".format(txts, timenow2, txts))
        os.system('clear')
        os.system("tshark -r {}/pcap/capture.{}.pcap -T fields -E header=y -e tcp.flags > {}/flags/test3.txt".format(txts, timenow2, txts))
        os.system('clear')
        mostoccuredip=subprocess.getoutput(r"cat /root/tcpdump/report/nodupes/report-nodup.{}.txt | sed '/^$/d' | uniq | head -1".format(timenow2))
        Unqi_Ips= subprocess.getoutput(r"cat /root/tcpdump/report/nodupes/report-nodup.{}.txt | wc -l".format(timenow2))
        dst_port = subprocess.getoutput(r"cat /root/tcpdump/dst/test.txt | head -2 | awk 'NR > 1 { print }'")
        src_port = subprocess.getoutput(r"cat /root/tcpdump/src/test2.txt | head -2 | awk 'NR > 1 { print }'")
        attack_flag5521 = subprocess.getoutput(r"cat /root/tcpdump/flags/test3.txt | head -2 | awk 'NR > 1 { print }'")
        pcaps22 = subprocess.getoutput(r"ls /root/tcpdump/pcap/ | wc -l")
        lastpcapv5 = subprocess.getoutput(r"ls /root/tcpdump/pcap/ | tail -n 1")
        lastcap = subprocess.getoutput(r"ls /root/tcpdump/ramdom/ | tail -n 1")
        iptableset=str(round(float(os.popen('''iptables -L | wc -l''').readline())))
        file = open(txts + "/ramdom/" + lastcap, "r")
        capture_file = file.read()
        attack_types = {
        " [UDP]": "17		",
        " [ICMP]": "1		",
        " [ICMP Dest Unreachable]": "1,17		",
        " [IPv4/Fragmented]": "4		",
        " [GRE]": "47		",
        " [IPX]": "111		",
        " [AH]": "51		",
        " [ESP]": "50		",
        " [OpenVPN Reflection]": "17		1194",
        " [VSE Flood/1]": "17		27015",
        " [RRSIG DNS Query Reflection]": "002e0001",
        " [ANY DNS Query Reflection]": "00ff0001",
        " [NTP Reflection]": "17		123",
        " [Chargen Reflection]": "17		19",
        " [MDNS Reflection]": "17		5353",
        " [BitTorrent Reflection]": "17		6881",
        " [CLDAP Reflection]": "17		389",
        " [STUN Reflection]": "17		3478",
        " [MSSQL Reflection]": "17		1434",
        " [SNMP Reflection]": "17		161",
        " [WSD Reflection]": "17		3702",
        " [DTLS Reflection]": "17		443		40",
        " [OpenAFS Reflection]": "17		7001",
        " [ARD Reflection]": "17		3283",
        " [BFD Reflection]": "17		3784",
        " [SSDP Reflection]": "17		1900",
        " [ArmA Reflection/1]": "17		2302",
        " [ArmA Reflection/2]": "17		2303",
        " [vxWorks Reflection]": "17		17185",
        " [Plex Reflection]": "17		32414",
        " [TeamSpeak Reflection]": "17		9987",
        " [Lantronix Reflection]": "17		30718",
        " [DVR IP Reflection]": "17		37810",
        " [Jenkins Reflection]": "17		33848",
        " [Citrix Reflection]": "17		1604",
        " [NAT-PMP Reflection]": "008000",
        " [Memcache Reflection]": "17		11211",
        " [NetBIOS Reflection]": "17		137",
        " [SIP Reflection]": "17		5060",
        " [Digiman Reflection]": "17		2362",
        " [Crestron Reflection]": "17		41794",
        " [CoAP Reflection]": "17		5683",
        " [BACnet Reflection]": "17		47808",
        " [FiveM Reflection]": "17		30120",
        " [Modbus Reflection]": "17		502",
        " [QOTD Reflection]": "17		17",
        " [ISAKMP Reflection]": "17		500",
        " [XDMCP Reflection]": "17		177",
        " [IPMI Reflection]": "17		623",
        " [Apple serialnumberd Reflection]": "17		626",
        " [UDPMIX DNS Flood]": "7065616365636f7270",
        " [Hex UDP Flood]": "2f78",
        " [Flood of 0x00]": "0000000000000000000",
        " [TSource Engine Query]": "54536f75726365",
        " [Known Botnet UDP Flood/1]": "52794d47616e67",
        " [Known Botnet UDP Flood/2]": "a6c300",
        " [OVH-RAPE/1]": "fefefefe",
        " [OVH-RAPE/2]": "4a4a4a4a",
        " [TeamSpeak Status Flood]": "545333494e49",
        " [Flood of 0xFF]": "fffffffffff",
        " [UDP getstatus Flood]": "676574737461747573",
        " [TCP Reflection from HTTPS/1]": "0x00000012		443",
        " [TCP Reflection from HTTPS/2]": "0x00000010		443",
        " [TCP Reflection from HTTP/1]": "0x00000012		80",
        " [TCP Reflection from HTTP/2]": "0x00000010		80",
        " [TCP Reflection from BGP/1]": "0x00000012		179",
        " [TCP Reflection from BGP/2]": "0x00000010		179",
        " [TCP Reflection from SMTP/1]": "0x00000012		465",
        " [TCP Reflection from SMTP/2]": "0x00000010		465",
        " [TCP SYN-ACK]": "0x00000012",
        " [TCP PSH-ACK]": "0x00000018",
        " [TCP RST-ACK]": "0x00000014",
        " [TCP FIN]": "0x00000001",
        " [TCP SYN]": "0x00000002",
        " [TCP PSH]": "0x00000008",
        " [TCP URG]": "0x00000020",
        " [TCP RST]": "0x00000004",
        " [TCP ACK]": "0x00000010",
        " [Unset TCP Flags]": "0x00000000",
        " [TCP SYN-ECN-CWR]": "0x000000c2",
        " [TCP SYN-ECN]": "0x00000042",
        " [TCP SYN-CWR]": "0x00000082",
        " [TCP SYN-PSH-ACK-URG]": "0x0000003a",
        " [TCP SYN-ACK-ECN-CWR]": "0x000000d2",
        " [TCP PSH-ACK-URG]": "0x00000038",
        " [TCP FIN-SYN-RST-PSH-ACK-URG]": "0x0000003f",
        " [TCP RST-ACK-URG-CWR-Reserved]": "0x000004b4",
        " [TCP SYN-PSH-URG-ECN-CWR-Reserved]": "0x000004ea",
        " [TCP FIN-RST-PSH-ECN-CWR-Reserved]": "0x00000ccd",
        " [TCP FIN-RST-PSH-ACK-URG-ECN-CWR-Reserved]": "0x00000cfd"
        }       
        attack_type = ''      
        for occurrences in attack_types:
            number = capture_file.count(attack_types[occurrences])

            if number > 500:
                percentage = 100 * float(number)/float(8000)
                attack_type = attack_type + " " + occurrences + f" [({str(percentage)}%)]"
                file = open("/root/tcpdump/attacktype/attacktype.txt", "w")
                file.write(attack_type)
                spoofing = "true"
        if attack_type == '':
            attack_type = "Undetermined"
            spoofing = "false"    
        file = open("/root/tcpdump/spoofing/spoofing.txt", "w")
        file.write(spoofing)
        ram=os.popen('''free -m | awk 'NR==2{printf "%.2f%%\t\t", $3*100/$2 }' ''').readline()
        CPU_Pct=str(round(float(os.popen('''top -n 1 -b | awk '/^%Cpu/{print $2}' ''').readline())))
        uptime=os.popen(''' uptime -p ''').readline()
        webhook2 = DiscordWebhook(url='yourwebhookhere', username="DDoS Notis")
        embed = DiscordEmbed(title="D(dos) Mitigation activated", url="https://temperhosting.co/", description="To protect your service from D(Dos) attacks we added mitigation", color=16624689)
        embed.set_footer(text=footerv3)
        embed.set_timestamp()
        embed.add_embed_field(name=':video_game: Server:', value="HOST1", inline=False)
        embed.add_embed_field(name=':microbe: Attack Type(s):',value=attack_type, inline=False)
        embed.add_embed_field(name=':level_slider: Packet Count',value=pps, inline=False)
        embed.add_embed_field(name=':dna: Uniq Ips',value=Unqi_Ips, inline=False) 
        embed.add_embed_field(name=':candle: Attack Flags(s):',value=attack_flag5521, inline=False)
        embed.add_embed_field(name=':telescope: Pcap',value="/root/tcpdump/pcap/" + lastpcapv5, inline=False) 
        embed.add_embed_field(name=':satellite_orbital: src port',value="attack from: " + src_port, inline=False)
        embed.add_embed_field(name=':camera_with_flash: attacked dst-port:',value="attack from: " + dst_port, inline=False)
        embed.add_embed_field(name=':page_with_curl: Number Of Pcaps',value=pcaps22, inline=False)
        embed.add_embed_field(name=':cloud_tornado: Spoofing?',value=spoofing, inline=False)
        embed.add_embed_field(name=':gear: Uptime:',value=uptime, inline=False)
        embed.add_embed_field(name=':shaved_ice: Iptable Sets (#):',value=iptableset, inline=False)
        embed.set_thumbnail(url=imagev11, inline=False)
        embed.set_footer(text=footerv3)
        webhook2.add_embed(embed)
        response = webhook2.execute()
        print(response)
        print(f"{ddosbanner}")
        time.sleep(0.6)
        print(f"{ddosbanner2}")
        time.sleep(0.75)
        print(f"{waitimev2}")
        time.sleep(60)
        