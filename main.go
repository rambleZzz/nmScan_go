package main

import (
	"github.com/rambleZzz/nmScan_go/core"
	"github.com/urfave/cli/v2"
	"log"
	"os"
)

func main() {

	var (
		model   string
		file    string
		port    string
		threads int
		oSqlite bool
		oStxt   bool
	)

	var app = &cli.App{
		Name:    "nmScan_go",
		Version: "v1.1",
		Usage:   "一款基于GO语言编写的支持调用fofa搜索结果、masscan json格式扫描结果、\n直接调用ip和ip:port格式4种方式进行nmap快速扫描，多种格式输出的主机端口信息的收集工具",
		UsageText: "nmScan -f ip.txt -m ip	(ip格式扫描模式，使用内置的常见端口扫描，并输出结果至sqlite)\n" +
			"nmScan -f ip.txt -m ip -p 22,445,3306,6379,8001-8005	(ip格式扫描模式，并指定端口扫描，并输出结果至sqlite)\n" +
			"nmScan -f ip.txt -m iport	(ip:port格式扫描模式，并输出结果至sqlite)\n" +
			"nmScan -f ip.txt -m fofa	(从fofa搜索ip开放端口扫描模式,fofa模式支持ip、ip/24、ip/25等格式内容，并输出结果至sqlite)\n" +
			"nmScan -f ip.json -m masjson	(解析masscan json扫描结果后的扫描模式，并输出结果至sqlite)\n" +
			"nmScan -f ip.txt -m fofa -oT	(输出结果至sqlite和txt) \n" +
			"\n" +
			"-oS表示输出到sqlite，此参数默认为true,不加也会输出,如果-oS false表示不输出至sqlite\n" +
			"-oT表示输出到txt，此参数默认为false,如果需要导出到文本需添加此参数 \n" +
			"f和m参数为必填项，其他参数为可选项，更多参数请参考GLOBAL OPTIONS",
		Action: core.TaskNew,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "file",
				Aliases:     []string{"f"},
				Usage:       "从txt或json文件中读取内容 ip.txt/ip.json",
				Destination: &file,
			},
			&cli.StringFlag{
				Name:        "model",
				Aliases:     []string{"m"},
				Usage:       "model参数决定目标解析及扫描方式(四选一) ip/iport/masjson/fofa",
				Destination: &model,
			},
			&cli.StringFlag{
				Name:        "port",
				Aliases:     []string{"p"},
				Usage:       "指定扫描的端口 如22,80,3306,8081-8090",
				Destination: &port,
			},
			&cli.IntFlag{
				Name:        "threads",
				Aliases:     []string{"t"},
				Value:       100,
				Usage:       "扫描线程数 ",
				Destination: &threads,
			},
			&cli.BoolFlag{
				Name:        "oSqlite",
				Aliases:     []string{"oS"},
				Value:       true,
				Usage:       "是否输出到sqlite",
				Destination: &oSqlite,
			},
			&cli.BoolFlag{
				Name:        "oTxt",
				Aliases:     []string{"oT"},
				Value:       false,
				Usage:       "是否输出到txt ",
				Destination: &oStxt,
			},
			// 省略剩余的 StringFlag...
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
