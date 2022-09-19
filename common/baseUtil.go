package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/goinggo/mapstructure"
	"os"
	"regexp"
	"strings"
	"time"
)

func JsonToMap(str string) (tMap map[string]interface{}) {
	//map 转json
	var tempMap map[string]interface{}
	err := json.Unmarshal([]byte(str), &tempMap)
	if err != nil {
		panic(err)
	}
	return tempMap
}

//判断是否为ip
func ChcekIsIp(ip string) bool {
	s := strings.Trim(ip, " ")
	regStr := `^(([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`
	if match, _ := regexp.MatchString(regStr, s); match {
		return true
	}
	return false
}

//判断是否为ip:port
func ChcekIsIport(iport string) bool {
	s := strings.Trim(iport, " ")
	regStr := `^(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})(\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})){3}:{1}(\d+)(,\d*)*$`
	if match, _ := regexp.MatchString(regStr, s); match {
		return true
	}
	return false
}

//判断是否为192.168.1.1/24 192.168.1.1/16
func ChcekIsIpmask(ipmask string) bool {
	s := strings.Trim(ipmask, " ")
	regStr := `^(([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([1-2][0-9]|3[0-2]|[1-9])$`
	if match, _ := regexp.MatchString(regStr, s); match {
		return true
	}
	return false
}

//判断是否为masscan扫描 json格式结果内容
func ChcekMasJson(iport string) bool {
	s := strings.Trim(iport, " ")
	regStr := `{(.*)"ip":(.*)("ports": \[ \{"port":)(.*)}$`
	if match, _ := regexp.MatchString(regStr, s); match {
		return true
	}
	return false
}

// 去重
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func GetCurrentPath() (dir string, err error) {
	return os.Getwd()
}

func Base64Encode(keyword string) string {
	input := []byte(keyword)
	encodeString := base64.StdEncoding.EncodeToString(input)
	return encodeString
}

func Base64Decode(encodeString string) (string, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(encodeString)
	return string(decodeBytes), err
}

func Slice2stringPort(slice []string) string {
	port := ""
	for _, s := range slice {
		port = port + s + ","
	}
	port = strings.TrimRight(port, ",")
	return port
}

func Slice2string(s string) string {
	return string([]byte(s))
}

//map转为HostInfo(struct)
func MapToStructHostInfo(ip string, ports string) HostInfo {
	mapInstance := make(map[string]string)
	mapInstance["Ip"] = ip
	mapInstance["Ports"] = ports
	var hostInfo HostInfo
	err := mapstructure.Decode(mapInstance, &hostInfo)
	if err != nil {
		fmt.Println(err)
	}
	return hostInfo
}

func GetCurrentRunPath() {
	CurrentRunPath, _ = GetCurrentPath()
}

func MkResultPath() {
	ResultPath = fmt.Sprintf("%s/result/task_%s/", CurrentRunPath, Ctime)
	exists := FolderExists(ResultPath)
	if !exists {
		DirCreate(ResultPath)
	}
}

func GetCurrentTimeString() string {
	return time.Now().Format("2006_01_02_15_04_05")
}

func BannerInit() {
	fmt.Println(banner)
	fmt.Println(nmScanAbout)
}
