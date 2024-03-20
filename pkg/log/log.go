package log

import (
	"log"
	"os"
)

var logger *log.Logger

func init() {
	file, err := os.OpenFile("emergency_script.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Failed to open log file", err)
	}
	logger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// LogMessage 使用定义的logger记录消息
func LogMessage(message string) {
	logger.Println(message)
}
