package main

import (
	"linuxAscan/pkg/banner"
	"linuxAscan/pkg/functions"
	"linuxAscan/pkg/log"
)

func main() {
	banner.PrintBanner()              // 使用banner包中的PrintBanner函数
	log.LogMessage("Program started") // 使用log包中的LogMessage函数记录程序开始执行的日志
	functions.ExecuteAllFunctions()
}
