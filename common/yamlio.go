package common

import (
	"github.com/spf13/viper"
	"log"
)

var configYaml = `#nmScan Yaml config
fofa:
  FOFA_EMAIL: xxxx@xxxx.com
  FOFA_KEY: xxxxxxxxxxxxx
  FOFA_SEARCH_SIZE: 2000	#fafa一次搜索返回的数量
scan:
  PortOpenCountLimit: 100	#可能防火墙过滤原因导致开放端口超过多少个,不对此IP结果进行导出
  NMAPsV: false	#是否进行nmap -sV 端口服务版本探测
`

func ReadYaml() {
	YamlName := CurrentRunPath + "/config.yaml"
	if CheckFileIsExist(YamlName) == false {
		WriteFile(YamlName, configYaml)
	}
	v := viper.New()
	v.AddConfigPath(CurrentRunPath)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		log.Println(err)
	}
	FOFA_EMAIL = v.GetString("fofa.FOFA_EMAIL")
	FOFA_KEY = v.GetString("fofa.FOFA_KEY")
	FOFA_SEARCH_SIZE = v.GetInt("fofa.FOFA_SEARCH_SIZE")
	PortOpenCountLimit = v.GetInt("scan.PortOpenCountLimit")
	NMAPsV = v.GetBool("scan.NMAPsV")
}
