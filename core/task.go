package core

import (
	"github.com/Ullaakut/nmap/v2"
	"github.com/rambleZzz/nmScan_go/common"
	"github.com/urfave/cli/v2"
	"log"
	"sync"
	"time"
)

func init() {
	common.BannerInit()
	common.GetCurrentRunPath()
	common.ReadYaml()
}

func TaskNew(cli *cli.Context) error {
	var host_list []common.HostInfo
	model := cli.String("m")
	inputFileName := cli.String("f")
	common.OutSqlFlag = cli.Bool("oS")
	common.OuTxtFlag = cli.Bool("oT")
	common.Threads = cli.Int("t")
	if cli.String("p") != "" {
		common.Ports = cli.String("p")
	}
	if inputFileName == "" {
		log.Println("[!]请输入要扫描的目标文件 -f xxx.txt 或 -f xxx.json")
		log.Fatalln("[!]请输入nmScan_go -h 查看详细命令参数")

	}
	f, err := common.ReadFile(inputFileName)
	f = common.RemoveDuplicate(f)
	if err == nil {
		switch model {
		case "ip":
			host_list = common.ParseIPtxt(f)
		case "iport":
			host_list = common.ParseIPPorts(f)
		case "masjson":
			host_list = common.ParseMasJson(f)
		case "fofa":
			host_list = common.ParseFofa(f)
		default:
			log.Println("[!]model参数决定目标解析及扫描方式(四选一) ip,iport,masjson,fofa")
			log.Println("[!]请输入正确的model值 例如 -m fofa")
			log.Fatalln("[!]请输入./nmScan_go -h 查看详细命令参数")
		}
	}
	start := time.Now()
	common.Ctime = common.GetCurrentTimeString()
	common.MkResultPath()
	log.Printf("[*]创建新任务: task_%s\n", common.Ctime)
	TaskRun(host_list)
	if common.OutSqlFlag == true {
		log.Printf("[nmap扫描结果输出至sqlite]: %s\n", common.O_sqlite_db)
	}
	if common.OuTxtFlag == true {
		log.Printf("[nmap hostinfo扫描结果输出至txt]: %s\n", common.O_Hostinfo_f)
		log.Printf("[nmap portinfo扫描结果输出至txt]: %s\n", common.O_Portinfo_f)
	}
	t := time.Now().Sub(start)
	log.Printf("[*]任务扫描结束,总耗时: %.2f 秒\n", t.Seconds())
	return nil
}

func TaskRun(host_list []common.HostInfo) {
	var wg sync.WaitGroup
	ch_host := make(chan common.HostInfo, len(host_list))
	ch_result := make(chan *nmap.Run, len(host_list))
	//发送扫描目标到通道
	for _, host := range host_list {
		wg.Add(1)
		ch_host <- host
	}
	//多线程调用nmap扫描
	for i := 0; i < common.Threads; i++ {
		go func() {
			for h := range ch_host {
				NmScan(h.Ip, h.Ports, ch_result, &wg)
				wg.Done()
			}
		}()
	}
	//接收并循环通道结果
	go func() {
		for result := range ch_result {
			common.ParseNmscanResult(result)
			wg.Done()
		}
	}()
	//通道等待与关闭
	wg.Wait()
	close(ch_host)
	close(ch_result)
}
