package functions

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/gookit/color"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func executeCommand(command string, args []string) string {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	if err != nil {
		// 返回标准错误输出，如果存在的话
		return fmt.Sprintf("错误: %v, 输出: %s", err, stderrBuf.String())
	}
	return strings.TrimSpace(stdoutBuf.String())
}

// systemInfoAndWrite collects system basic information and writes it to a file
func systemInfoAndWrite() {
	kernel := executeCommand("uname", []string{"-r"})

	// Reading from /etc/os-release to get OS information
	release, err := os.ReadFile("/etc/os-release")
	if err != nil {
		fmt.Printf("Error reading /etc/os-release: %v\n", err)
		return
	}
	osInfo := string(release) // Convert to string for further processing

	hostname, _ := os.Hostname()
	dateload := executeCommand("uptime", []string{"-p"})
	usersRaw := executeCommand("uptime", []string{})
	users := strings.Split(usersRaw, ",")[1] // Adjust to match actual output
	username := executeCommand("whoami", []string{})
	systemName := executeCommand("uname", []string{"-o"})

	info := fmt.Sprintf(`
##############   系统基础信息 #######

------------------------------------
|内核信息:        %s           
------------------------------------
|操作系统信息:   %s        
------------------------------------
|主机名称:      %s      
------------------------------------
|当前时间及运行时间:   %s        
------------------------------------
|当前登录用户数:   %s        
------------------------------------
|系统名称:      %s      
------------------------------------
|当前登录用户:      %s      
------------------------------------
`, kernel, strings.Split(osInfo, "\n")[0], hostname, dateload, strings.TrimSpace(users), systemName, username)

	// Ensure the results directory exists
	os.MkdirAll("results", os.ModePerm)

	// Open the file, creating it if it does not exist
	filePath := filepath.Join("results", "info.txt")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	// Write the information to the file
	_, err = file.WriteString(info)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
	color.Green.Println(info)
}

// detectPackageManager 尝试检测操作系统类型并返回相应的包管理器和更新命令
func detectPackageManager() (string, string, string) {
	// 尝试使用 /etc/os-release 文件检测
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		osReleaseContent := string(content)
		if strings.Contains(osReleaseContent, "ID=debian") || strings.Contains(osReleaseContent, "ID=ubuntu") || strings.Contains(osReleaseContent, "ID_LIKE=debian") {
			return "apt-get", "sudo apt-get update", "sudo apt-get install -y"
		} else if strings.Contains(osReleaseContent, "ID=fedora") || strings.Contains(osReleaseContent, "ID=centos") || strings.Contains(osReleaseContent, "ID=like=fedora") {
			return "yum", "sudo yum makecache", "sudo yum install -y"
		}
	}

	// 尝试使用 lsb_release 命令检测
	cmd := exec.Command("lsb_release", "-si")
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		if strings.Contains(strings.ToLower(out.String()), "ubuntu") || strings.Contains(strings.ToLower(out.String()), "debian") {
			return "apt-get", "sudo apt-get update", "sudo apt-get install -y"
		} else if strings.Contains(strings.ToLower(out.String()), "centos") || strings.Contains(strings.ToLower(out.String()), "fedora") {
			return "yum", "sudo yum makecache", "sudo yum install -y"
		}
	}

	// 默认或未知情况
	return "", "", ""
}

// installPackages 尝试安装一组预定义的软件包
func installPackages() {
	packages := []string{
		"net-tools",
		"lrzsz",
		"wget",
		"silversearcher-ag",
		"Rootkit",
		"gcc-c++",
		"glibc-static",
		"lynis",
		"rkhunter",
	}

	pkgManager, updateCmd, installCmdPrefix := detectPackageManager()
	if pkgManager == "" {
		fmt.Println("Unsupported OS or unable to detect package manager.")
		return
	}

	// 打印当前操作系统类型
	fmt.Printf("------------------------------------\n|检测到包管理器: %s\n------------------------------------\n", pkgManager)

	// 示例: 合并软件包名称，并一次性安装所有软件包
	installCmd := fmt.Sprintf("%s; %s %s", updateCmd, installCmdPrefix, strings.Join(packages, " "))
	fmt.Println("执行安装命令:", installCmd)
	cmd := exec.Command("bash", "-c", installCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("安装过程中出现错误: %v\n", err)
	} else {
		color.Green.Println("软件包安装成功")
	}
}

// getHighCPUUsageProcesses finds and logs processes with CPU usage over 70%.
func getHighCPUUsageProcesses() {
	// Using ps command to get process info, then filtering with awk for processes over 70% CPU usage
	command := `ps -eo pid,comm,%cpu --sort=-%cpu | awk 'NR>1 && $3 > 10 {print $1 " " $2 " " $3}'`
	output := executeCommand("bash", []string{"-c", command})

	if output == "" {
		fmt.Println("没有发现CPU占用超过10%的进程")
		return
	}

	// Process each line of output
	lines := strings.Split(output, "\n")
	info := "##############   进程信息 #######\n\n"

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		pid, comm, cpuUsage := parts[0], parts[1], parts[2]

		// Get the process's command line path
		commandPath := executeCommand("bash", []string{"-c", fmt.Sprintf("readlink -f /proc/%s/exe", pid)})

		// Get the process's command line arguments
		cmdlineBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
		if err != nil {
			fmt.Printf("Failed to read cmdline for PID %s: %v\n", pid, err)
			continue
		}
		cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

		processInfo := fmt.Sprintf("---------------CPU只占用滤---------------------\n"+
			"|CPU占用率:        %s%%\n"+
			"|进程pid:       %s\n"+
			"|进程名:      %s\n"+
			"|进程对应文件位置: %s\n"+
			"|进程执行的命令参数: %s\n"+
			"------------------------------------\n",
			cpuUsage, pid, comm, commandPath, cmdline)

		info += processInfo

		// Print to console
		color.Green.Println(processInfo)
	}

	// Ensure the results directory exists
	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Printf("创建目录失败：%v\n", err)
		return
	}

	// Append the information to the file
	filePath := filepath.Join("results", "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法打开文件：%v\n", err)
		return
	}
	defer file.Close()

	// Write the information to the file
	if _, err := file.WriteString(info); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	} else {
		fmt.Println("进程信息已追加到文件")
	}
}

func formatLoginOutput(output string) string {
	lines := strings.Split(output, "\n")
	var formattedLines []string
	for i := 0; i < len(lines); i += 2 {
		if i+1 < len(lines) {
			formattedLines = append(formattedLines, lines[i]+" | "+lines[i+1])
		} else {
			formattedLines = append(formattedLines, lines[i])
		}
	}
	return strings.Join(formattedLines, "\n")
}

// getAccountSecurityInfo collects and prints account security-related information.
func getAccountSecurityInfo() {
	// Get last login users and format output
	lastLoginCommand := `last -a | head -n -2 | awk '{print $1, $5, $6, $7, $8, $9}'`
	lastLoginOutput := executeCommand("bash", []string{"-c", lastLoginCommand})
	formattedLastLoginOutput := formatLoginOutput(lastLoginOutput)

	// Other security-related information
	uidZeroUsers := executeCommand("bash", []string{"-c", "getent passwd | awk -F: '$3 == 0 {print $1}'"})
	UIDformattedLastLoginOutput := formatLoginOutput(uidZeroUsers)
	loginUsers := executeCommand("bash", []string{"-c", "cat /etc/passwd | grep -Ev 'nologin$|false$' | cut -d: -f1"})
	formatLoginUser := formatLoginOutput(loginUsers)
	sudoUsers := executeCommand("bash", []string{"-c", "getent group sudo | cut -d: -f4"})
	formatsudoUser := formatLoginOutput(sudoUsers)
	nopasswd := executeCommand("bash", []string{"-c", "cat /etc/sudoers | grep -v '^#' | sed '/^$/d' | grep 'ALL' --color=never | cut -d: -f1"})
	formatnopasswd := formatLoginOutput(nopasswd)
	// Assembling the information
	info := fmt.Sprintf(`##############   账号安全 #######

------------------------------------
|最近远程和本地登录过用户tty/tps:
%s
------------------------------------
|UID为0的用户:
%s
------------------------------------
|允许登陆的用户：
%s
------------------------------------
|存在sudo权限的用户:
%s
------------------------------------
|存在免密执行sudo权限的用户:
%s
------------------------------------
`, formattedLastLoginOutput, UIDformattedLastLoginOutput, formatLoginUser, formatsudoUser, formatnopasswd)

	// Print to console in green color
	color.New(color.FgGreen).Println(info)

	// Ensure the results directory exists
	os.MkdirAll("results", os.ModePerm)

	// Append the information to the file
	filePath := filepath.Join("results", "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Unable to open file: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(info); err != nil {
		fmt.Printf("Failed to write to file: %v\n", err)
	} else {
		fmt.Println("文件已写入")
	}
}

// ThreatbookResponse 定义了从微步API返回的数据结构
type ThreatbookResponse struct {
	Data map[string]struct {
		IsMalicious bool `json:"is_malicious"`
	} `json:"data"`
}

// checkIPMaliciousness 查询给定IP地址是否为恶意地址
func checkIPMaliciousness(ip, apiKey string) (bool, error) {
	url := fmt.Sprintf("https://api.threatbook.cn/v3/scene/ip_reputation?apikey=%s&resource=%s", apiKey, ip)
	response, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	var result ThreatbookResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return false, err
	}

	data, exists := result.Data[ip]
	if !exists {
		return false, fmt.Errorf("IP地址信息不存在")
	}

	return data.IsMalicious, nil
}
func getProcessPathByPID(pid string) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", pid))
	if err != nil {
		return "", err
	}
	return path, nil
}

// getEstablishedConnections 检索并显示所有ESTABLISHED状态的外联连接
func getEstablishedConnections() {
	fmt.Print("请输入您的API密钥：")
	reader := bufio.NewReader(os.Stdin)
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)

	output, err := exec.Command("bash", "-c", "netstat -antp | grep ESTABLISHED").CombinedOutput()
	if err != nil {
		fmt.Println("执行netstat命令失败:", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	infoHeader := "##############外联IP检查##############\n\n------------------------------------\n|外联IP        端口    进程ID    进程位置                                  进程程序    微步分析是否为恶意IP\n"
	var infoLines []string

	re := regexp.MustCompile(`tcp\s+\d+\s+\d+\s+\d+\.\d+\.\d+\.\d+:\d+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+ESTABLISHED\s+(\d+)/(\S+)`)

	for _, line := range lines {
		if line == "" {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}

		remoteIP, remotePort, pid, procName := matches[1], matches[2], matches[3], matches[4]
		procPath, _ := getProcessPathByPID(pid)
		isMalicious, err := checkIPMaliciousness(remoteIP, apiKey)
		maliciousStatus := "不是"
		if err == nil && isMalicious {
			maliciousStatus = "是"
		}

		infoLine := fmt.Sprintf("%-15s %-7s %-8s %-40s %-10s %s", remoteIP, remotePort, pid, procPath, procName, maliciousStatus)
		infoLines = append(infoLines, infoLine)
	}

	fullInfo := infoHeader + strings.Join(infoLines, "\n") + "\n------------------------------------"
	color.New(color.FgGreen).Println(fullInfo)

	// Append the information to the file
	filePath := filepath.Join("results", "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法打开文件：%v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(fullInfo); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	} else {
		fmt.Println("外联IP检查信息已追加到文件。")
	}
}

// 嵌入assets文件夹中的hm二进制文件和cache.db文件
//
//go:embed assets/hm assets/cache.db
var embeddedFiles embed.FS

// appendToFile 追加内容到指定的文件
func appendToFile(content, filePath string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法打开文件：%v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	}
}

// createTempFile 从嵌入的文件系统中读取文件并写入到指定的输出路径
func createTempFile(embeddedPath, outputPath string) error {
	// 从嵌入的文件系统中读取文件数据
	fileData, err := fs.ReadFile(embeddedFiles, embeddedPath)
	if err != nil {
		fmt.Printf("读取嵌入文件失败: %v\n", err)
		return err
	}

	// 写入数据到输出路径
	if err := ioutil.WriteFile(outputPath, fileData, 0755); err != nil {
		fmt.Printf("写入临时文件失败: %v\n", err)
		return err
	}

	return nil
}

// executeEmbeddedHM 执行嵌入的HM扫描命令
func executeEmbeddedHM() {
	fmt.Println("请输入要扫描webshell的路径：")
	var scanPath string
	fmt.Scanln(&scanPath) // 从标准输入接收扫描路径

	tmpDir, err := ioutil.TempDir("", "hm")
	if err != nil {
		fmt.Println("创建临时目录失败:", err)
		return
	}
	defer os.RemoveAll(tmpDir)

	// 解压hm二进制文件到临时目录
	hmPath := filepath.Join(tmpDir, "hm")
	if err := createTempFile("assets/hm", hmPath); err != nil {
		return
	}

	// 解压cache.db到临时目录
	cacheDBPath := filepath.Join(tmpDir, "cache.db")
	if err := createTempFile("assets/cache.db", cacheDBPath); err != nil {
		return
	}

	// 执行hm命令进行扫描
	cmds := exec.Command("chmod", "777", hmPath)
	_, errs := cmds.CombinedOutput()
	if errs != nil {
		fmt.Printf("修改权限失败: %v\n", errs)
		return
	}

	// 设置命令和工作目录
	cmd := exec.Command(hmPath, "scan", scanPath)
	cmd.Dir = tmpDir // 设置工作目录为临时目录
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("执行命令失败: %v, 输出: %s\n", err, output)
		return
	}

	// 读取result.csv文件
	resultCsvPath := filepath.Join(tmpDir, "result.csv")
	csvContent, err := ioutil.ReadFile(resultCsvPath)
	if err != nil {
		fmt.Printf("读取result.csv失败: %v\n", err)
		return
	}

	// 追加输出到results/info.txt和控制台
	resultContent := string(csvContent)
	appendToFile(resultContent, "results/info.txt")
	color.Green.Println("##############webshell扫描结果##############")
	color.Green.Println(resultContent)
}
func scanWithLynis() {
	fmt.Println("#############lynis扫描##############")

	// 使用现有的executeCommand函数执行lynis命令
	output := executeCommand("sudo", []string{"lynis", "audit", "system"})

	// 打印扫描过程
	color.Green.Println(output)

	// 确保results目录存在
	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Printf("创建results目录失败: %v\n", err)
		return
	}

	// 将结果追加到文件
	filePath := filepath.Join("results", "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("打开文件时出错: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString("#############lynis扫描##############\n" + output + "\n"); err != nil {
		fmt.Printf("写入文件失败: %v\n", err)
	} else {
		fmt.Println("lynis扫描结果已追加到文件。")
	}
}

func scanCronAndServices() {
	fmt.Println("#############计划任务/开机自启服务##############")

	// 收集crontab计划任务
	cronJobs := executeCommand("bash", []string{"-c", "crontab -l"})
	if cronJobs == "" {
		cronJobs = "No crontab for this user"
	}

	// 收集系统服务状态
	// 注意: 对于不同的系统，命令可能有所不同
	services := executeCommand("bash", []string{"-c", "systemctl list-unit-files --type=service | grep enabled"})
	if services == "" {
		services = "No enabled services found"
	}

	// 组合信息
	info := fmt.Sprintf("#############计划任务/开机自启服务##############\n\n"+
		"--- Crontab Jobs ---\n%s\n\n"+
		"--- Enabled Services ---\n%s\n",
		cronJobs, services)

	// 打印信息
	color.Green.Println(info)

	// 追加到文件
	filePath := filepath.Join("results", "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("打开文件时出错: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(info); err != nil {
		fmt.Printf("写入文件失败: %v\n", err)
	} else {
		fmt.Println("计划任务/开机自启服务信息已追加到文件。")
	}
}

// appendToFile 将给定的内容追加到指定的文件中，确保目录存在
func appendToFiles(filePath, content string) {
	// 确保文件所在的目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("创建目录失败：%v\n", err)
		return
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法打开文件：%v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	} else {
		fmt.Printf("信息已追加到文件：%s\n", filePath)
	}
}

// scanRecentFiles 扫描指定路径下最近三天内增加或修改的文件
func scanRecentFiles() {
	fmt.Print("请输入要检查的文件路径：")
	reader := bufio.NewReader(os.Stdin)
	path, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("读取路径输入时出错:", err)
		return
	}
	path = strings.TrimSpace(path)

	// 构建find命令的字符串
	findAddedCmd := fmt.Sprintf("find %s -type f -ctime -3", path)
	findModifiedCmd := fmt.Sprintf("find %s -type f -mtime -3", path)

	addedFiles := executeCommand("bash", []string{"-c", findAddedCmd})
	modifiedFiles := executeCommand("bash", []string{"-c", findModifiedCmd})

	result := fmt.Sprintf("#############文件检查##############\n\n"+
		"--- 最近三天增加的文件 ---\n%s\n\n"+
		"--- 最近三天修改的文件 ---\n%s\n", addedFiles, modifiedFiles)

	// 打印到控制台
	color.Green.Println(result)

	// 追加到文件
	appendToFiles("results/info.txt", result)
}

func askForLogFilePath() string {
	fmt.Print("请输入SSH日志文件的完整路径: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

func appendToInfoFile(content string) {
	dir := "results"
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("创建目录%s失败：%v\n", dir, err)
		return
	}

	filePath := filepath.Join(dir, "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法打开文件：%v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	}
}
func analyzeSSHLog() {
	logFilePath := askForLogFilePath()
	if logFilePath == "" {
		color.Red.Println("未提供有效的日志文件路径。")
		return
	}

	file, err := os.Open(logFilePath)
	if err != nil {
		color.Red.Printf("打开日志文件失败：%v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var results strings.Builder

	// 初始化正则表达式
	successPattern := regexp.MustCompile(`Accepted (\w+) for (\w+) from (\S+) port \d+ ssh2`)
	failedPattern := regexp.MustCompile(`Failed password for (invalid user )?(\w+) from (\S+) port \d+ ssh2`)
	userAddPattern := regexp.MustCompile(`new user: name=(\w+), .*`)
	userDelPattern := regexp.MustCompile(`userdel.*?: delete user '(\w+)'`)
	suPattern := regexp.MustCompile(`su: pam_unix\(su:session\): session opened for user (\w+) by \w+\(uid=(\d+)\)`)
	sudoPattern := regexp.MustCompile(`sudo: \s*(\w+) : .* COMMAND=(.+)`)

	// 存储结果
	loginAttempts := make(map[string]int) // 登录尝试次数，包括成功和失败
	userAdds := make([]string, 0)
	userDels := make([]string, 0)
	suRecords := make([]string, 0)
	sudoRecords := make([]string, 0)

	for scanner.Scan() {
		line := scanner.Text()

		if matches := successPattern.FindStringSubmatch(line); matches != nil {
			loginAttempts[matches[3]] = 0 // 记录成功的登录尝试，次数置为0
		} else if matches := failedPattern.FindStringSubmatch(line); matches != nil {
			loginAttempts[matches[3]]++ // 记录失败的登录尝试，次数累加
		}

		if matches := userAddPattern.FindStringSubmatch(line); matches != nil {
			userAdds = append(userAdds, matches[1])
		} else if matches := userDelPattern.FindStringSubmatch(line); matches != nil {
			userDels = append(userDels, matches[1])
		} else if matches := suPattern.FindStringSubmatch(line); matches != nil {
			suRecords = append(suRecords, matches[1])
		} else if matches := sudoPattern.FindStringSubmatch(line); matches != nil {
			sudoRecords = append(sudoRecords, fmt.Sprintf("%s ran %s", matches[1], matches[2]))
		}
	}

	// 构造最终的输出字符串
	results.WriteString(color.Green.Sprint("登录名\tIP\t\t\t是否登录成功\t\t\t\t失败次数\t\t\t\n"))
	for ip, attempts := range loginAttempts {
		success := "否"
		if attempts == 0 {
			success = "是"
		}
		results.WriteString(fmt.Sprintf("root\t%s\t\t%s\t%d次\n", ip, success, attempts))
	}

	// 其他记录...
	// 此处添加用户添加、删除、su和sudo记录的输出逻辑（类似之前的实现）
	// 输出结果
	results.WriteString(color.Green.Sprint("#############用户创建记录##############\n"))
	for _, user := range userAdds {
		results.WriteString(fmt.Sprintf("%s\n", user))
	}

	results.WriteString(color.Green.Sprint("\n#############用户删除记录##############\n"))
	for _, user := range userDels {
		results.WriteString(fmt.Sprintf("%s\n", user))
	}

	results.WriteString(color.Green.Sprint("\n#############su使用记录##############\n"))
	for _, record := range suRecords {
		results.WriteString(fmt.Sprintf("%s\n", record))
	}

	results.WriteString(color.Green.Sprint("\n#############sudo授权记录##############\n"))
	for _, record := range sudoRecords {
		results.WriteString(fmt.Sprintf("%s\n", record))
	}
	fmt.Println(results.String())
	appendToInfoFile(results.String())
}

type AttackPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// appendToInfoFiles 追加内容到info.txt文件
func appendToInfoFiles(content string) {
	dir := "results"
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		fmt.Printf("创建目录%s失败：%v\n", dir, err)
		return
	}
	filePath := fmt.Sprintf("%s/web.txt", dir)
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("打开文件失败：%v\n", err)
		return
	}
	defer file.Close()
	if _, err := file.WriteString(content + "\n"); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	}
}

// analyzeWebLog 分析Web日志
func analyzeWebLog() {
	fmt.Print("请输入Web日志文件的完整路径: ")
	var logFilePath string
	fmt.Scanln(&logFilePath)

	file, err := os.Open(logFilePath)
	if err != nil {
		fmt.Printf("打开日志文件失败：%v\n", err)
		return
	}
	defer file.Close()

	var attackPatterns = []AttackPattern{
		{"SQL Injection", regexp.MustCompile(`(?i)(union|select|insert\s+into|update|delete\s+from|concat\(|updatexml\(|extractvalue\(|substring\(|sleep\()`)},
		{"XSS Injection", regexp.MustCompile(`(?i)(<script.*?>.*?</script>|<svg.*?>|<img.*?onerror=|javascript:|onmouseover=|onload=)`)},
		{"File Upload", regexp.MustCompile(`(?i)(\.(php|jsp|aspx|cfm|cgi)\s*upload)`)},
		{"Command Injection", regexp.MustCompile(`(?i)(;|\||&&|` + "`" + `)\s*(nslookup|ping|wget|curl)`)},
		{"Directory Traversal", regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow)`)},
		{"Remote File Inclusion", regexp.MustCompile(`(?i)(include\s*(\(|\s)|require\s*(\(|\s)).*?(http|https|ftp)://`)},
		{"Server-Side Request Forgery (SSRF)", regexp.MustCompile(`(?i)(url=|uri=|path=).*?(http|https)://`)},
		{"Open Redirect", regexp.MustCompile(`(?i)(url=|uri=|path=|redirect=|dest=).*?(http|https)://`)},
		{"XML External Entity (XXE)", regexp.MustCompile(`(?i)(<!ENTITY.*SYSTEM.*)`)},
		{"Local File Inclusion (LFI)", regexp.MustCompile(`(?i)(include\s*(\(|\s)|require\s*(\(|\s)).*?(\.\./|\.\.\\)`)},
		{"File Leakage", regexp.MustCompile(`(?i)\.(zip|xml|config|env|tar|gz|tgz|bz2|sql|bak|git|svn|htaccess|htpasswd|ini|log|sh|yaml|yml|json)($|\s|\?|=|&)`)},
	}

	scanner := bufio.NewScanner(file)
	results := "#############web日志分析##############\n"

	for scanner.Scan() {
		line := scanner.Text()
		for _, ap := range attackPatterns {
			if ap.Pattern.MatchString(line) {
				results += fmt.Sprintf("%s漏洞: %s\n", ap.Name, line)
				// 只报告一次每种攻击类型
				break
			}
		}
	}
	fmt.Println()
	appendToInfoFiles(results) // 将结果写入文件
}

func ExecuteAwkCommand() {
	// 替换为实际的日志文件路径
	logFilePath := "results/web.txt"
	// 构建 awk 命令字符串
	awkCmdStr := fmt.Sprintf("awk -F \" \" '{printf \"%%-15s %%-10s %%-10s %%-10s %%-10s %%-10s %%-10s %%-10s %%-20s\\n\", $1, $2, $3, $6, $7, $8, substr($9, 1, 100), $10, $11}' %s", logFilePath)

	// 执行 awk 命令
	cmd := exec.Command("bash", "-c", awkCmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("执行 awk 命令失败: %v\n", err)
		return
	}

	// 打印结果
	fmt.Println("#############web日志分析结果##############")
	fmt.Println(string(output))

	// 追加到 info.txt
	appendToInfoFileT(string(output))

	// 删除 web.txt 文件
	os.Remove("results/web.txt")
}

// appendToInfoFile 追加内容到 info.txt 文件
func appendToInfoFileT(content string) {
	dir := "results"
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("创建目录%s失败：%v\n", dir, err)
		return
	}

	filePath := filepath.Join(dir, "info.txt")
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法打开文件：%v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		fmt.Printf("写入文件失败：%v\n", err)
	}
}

func ExecuteAllFunctions() {
	systemInfoAndWrite()
	installPackages()
	getHighCPUUsageProcesses()
	getAccountSecurityInfo()
	getEstablishedConnections()
	executeEmbeddedHM()
	scanCronAndServices()
	scanRecentFiles()
	analyzeSSHLog()
	analyzeWebLog()
	ExecuteAwkCommand()
	scanWithLynis()

}
