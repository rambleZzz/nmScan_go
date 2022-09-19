package common

import (
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/rambleZzz/nmScan_go/plugins"
	"log"
	"net"
	"strconv"
	"strings"
)

func ParseIPPorts(f []string) (hlist []HostInfo) {
	var ip, port string
	var hInfo HostInfo
	var hList []HostInfo
	ip_ports := make(map[string]string)
	for _, ipPort := range f {
		if ChcekIsIport(ipPort) {
			s := strings.Split(ipPort, ":")
			ip = s[0]
			port = s[1]
			if _, ok := ip_ports[ip]; ok {
				port = ip_ports[ip] + "," + port
			}
			ip_ports[ip] = port
		} else {
			log.Fatalf("[!]ip:port格式不正确:\"%v\", (-m iport 模式内容格式应为IP:Port，如 127.0.0.1:3306)\n", ipPort)
		}
	}
	for i, p := range ip_ports {
		p = Slice2stringPort(RemoveDuplicate(strings.Split(p, ",")))
		hInfo = MapToStructHostInfo(i, p)
		hList = append(hList, hInfo)
	}
	return hList
}

func ParseIPtxt(f []string) (hlist []HostInfo) {
	var host HostInfo
	var hList []HostInfo
	for _, ip := range f {
		//判断是不是ip格式，如果不是IP刚退出
		parseIP := net.ParseIP(ip)
		if parseIP != nil {
			host.Ip = ip
			host.Ports = Ports
			hList = append(hList, host)
		} else {
			log.Fatalf("[!]ip格式不正确:\"%v\", (-m ip 模式内容格式应仅为IP，如 127.0.0.1)\n", ip)
		}
	}
	return hList
}

func ParseMasJson(f []string) (hlist []HostInfo) {
	var ip, port string
	var hInfo HostInfo
	var hList []HostInfo
	var exclude_port_ip []string
	s := make(map[string]interface{})
	ip_ports := make(map[string]string)
	//解析masscan json格式扫描结果为 map[ip:127.0.0.1 port:8080] 再转struct 加入slice
	for _, l := range f {
		if strings.HasPrefix(l, "{") {
			if ChcekMasJson(l) {
				s = JsonToMap(l)
				ip = s["ip"].(string)
				port = strconv.Itoa(int(s["ports"].([]interface{})[0].(map[string]interface{})["port"].(float64)))
				//存在相同的的key，value进行字符串连接 127.0.0.1:80 127.0.0.1:8080 >  127.0.0.1:80,8080
				if _, ok := ip_ports[ip]; ok {
					port = ip_ports[ip] + "," + port
				}
				ip_ports[ip] = port
			} else {
				log.Fatalf("[!]json文本内容不正确:\"%v\", (-m masjson 模式内容格式应为IP，如 {   \"ip\": \"127.0.0.1\",   \"timestamp\": \"1660632253\", \"ports\": [ {\"port\": 8080, \"proto\": \"tcp\", \"status\": \"open\", \"reason\": \"syn-ack\", \"ttl\": 124} ] })\n", l)
			}
		}
	}
	for i, p := range ip_ports {
		//为避免防火墙策略存活所有端口，alive_port_count参数控制超过多少的个开放端口的IP舍去不扫描，并加入exclude_port_ip统计IP
		alive_port_count := len(strings.Split(p, ","))
		if alive_port_count < PortOpenCountLimit {
			hInfo = MapToStructHostInfo(i, p)
			hList = append(hList, hInfo)
		} else {
			exclude_port_ip = append(exclude_port_ip, i)
		}
	}
	if len(exclude_port_ip) > 0 {
		log.Printf("过滤不扫描的IP: %v\n", exclude_port_ip)
	}
	return hList
}

func ParseFofaOneIp(serchIp string, fClient *plugins.Client) (hlist []HostInfo) {
	var hInfo HostInfo
	var hList []HostInfo
	ip_ports := make(map[string]string)
	if ChcekIsIp(serchIp) == false && ChcekIsIpmask(serchIp) == false {
		log.Fatalf("[!]ip/mask格式不正确:\"%v\"  (-m fofa 模式内容格式应为ip 或 ip/mask，如192.168.1.1 或 192.168.1.1/24)\n", serchIp)
	}
	keyword := fmt.Sprintf("ip=\"%s\"", serchIp)
	_, results := fClient.Search(Base64Encode(keyword))
	for _, result := range results {
		ip := result.Ip
		port := result.Port
		if _, ok := ip_ports[ip]; ok {
			port = ip_ports[ip] + "," + port
		}
		ip_ports[ip] = port
	}
	for ip, port := range ip_ports {
		port = Slice2stringPort(RemoveDuplicate(strings.Split(port, ",")))
		hInfo = MapToStructHostInfo(ip, port)
		hList = append(hList, hInfo)
	}
	return hList
}

func ParseFofa(f []string) (hlist []HostInfo) {
	if plugins.FofaAuth(FOFA_EMAIL, FOFA_KEY) == true {
		log.Println("[*]fofa账户认证成功")
	} else {
		log.Fatal("[!]fofa账户认证失败,请检查config.yaml配置文件的FOFA_EMAIL和FOFA_KEY是否正确！")
	}
	fClient := plugins.NewFofaClient(FOFA_EMAIL, FOFA_KEY)
	fClient.SetSize(FOFA_SEARCH_SIZE)
	var hList []HostInfo
	for _, s := range f {
		r := ParseFofaOneIp(s, fClient)
		hList = append(hList, r...)
	}
	return hList
}

func ParseNmscanResult(result *nmap.Run) (HostInfo, []PortInfo) {
	var portInfo PortInfo
	var hostInfo HostInfo
	var pInfo []PortInfo
	var h_ports []string
	var ip string
	var port_open_num int
	//解析nmap扫描结果
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		ip = host.Addresses[0].Addr
		log.Printf("[%s][nmap扫描结果]:\n", ip)
		for _, port := range host.Ports {
			if port.State.State == "open" {
				fmt.Printf("	Port %v/%v %v %v %v %v\n", port.ID, port.Protocol, port.State, port.Service.Name, port.Service.Product, port.Service.Version)
				portID := strconv.Itoa(int(port.ID))
				portInfo.Ip = ip
				portInfo.Port = portID
				portInfo.Protocol = port.Protocol
				portInfo.State = port.State.State
				portInfo.ServiceName = port.Service.Name
				portInfo.ServiceProduct = port.Service.Product
				portInfo.ServiceVersion = port.Service.Version
				h_ports = append(h_ports, portID)
				pInfo = append(pInfo, portInfo)
				if OuTxtFlag == true {
					OutPortinfo2txt(portInfo)
				}
			}
		}
		port_open_num = len(h_ports)
		if port_open_num < PortOpenCountLimit {
			if port_open_num > 0 {
				hostInfo.Ip = host.Addresses[0].Addr
				hostInfo.Ports = strings.Join(h_ports, ",")
				fmt.Printf("	[%s 开放端口统计]: %v\n", ip, hostInfo.Ports)
			} else {
				fmt.Printf("	[%s 开放端口统计]: 无端口开放\n", ip)
			}
		} else {
			fmt.Printf("	[%s 开放端口统计]: 可能防火墙过滤原因导致开放端口超过%d个,不对此IP结果进行导出\n", ip, PortOpenCountLimit)
		}

	}
	fmt.Printf("	[%s 端口扫描用时]: %.2f 秒\n", ip, result.Stats.Finished.Elapsed)
	if port_open_num > 0 && port_open_num < PortOpenCountLimit && OutSqlFlag == true {
		Out2sqlite(hostInfo, pInfo)
	}
	if port_open_num > 0 && port_open_num < PortOpenCountLimit && OuTxtFlag == true {
		OutHostinfo2txt(hostInfo)
	}
	return hostInfo, pInfo
}
