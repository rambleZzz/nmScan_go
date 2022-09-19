package common

import "fmt"

//输出ip:port1,port2,port3信息到文本
func OutHostinfo2txt(hInfo HostInfo) {
	O_Hostinfo_f = fmt.Sprintf("%s%s", ResultPath, O_Host_Name)
	s := fmt.Sprintf("%s:%s\n", hInfo.Ip, hInfo.Ports)
	WriteFile(O_Hostinfo_f, s)
}

//输出端口信息到文本
func OutPortinfo2txt(portInfo PortInfo) {
	O_Portinfo_f = fmt.Sprintf("%s%s", ResultPath, O_Port_Name)
	s := fmt.Sprintf("%s %s %s %s %s %s %s\n", portInfo.Ip, portInfo.Port, portInfo.Protocol, portInfo.State, portInfo.ServiceName, portInfo.ServiceProduct, portInfo.ServiceVersion)
	WriteFile(O_Portinfo_f, s)
}

//输出结果至sqlite
func Out2sqlite(hostInfo HostInfo, pInfo []PortInfo) {
	O_sqlite_db = fmt.Sprintf("%s%s", ResultPath, O_sqlite_Name)
	InsertSqlite(hostInfo, pInfo)
}
