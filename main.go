package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ulikunitz/xz"
	"github.com/sirupsen/logrus"
	"github.com/gorilla/websocket"
)

// 常量定义
const (
	Version        = "1.0.0"
	DefaultLockDir = "/var/lock"
	DefaultTmpDir  = "/var/run/ezota"
	DefaultLogFile = "/tmp/ezota.log"
	GithubRepo     = "sirpdboy/openwrt"
	GithubAPI      = "https://api.github.com/repos/" + GithubRepo + "/releases"
	GithubMirror   = "https://gh-api.p3terx.com/repos/" + GithubRepo + "/releases"
)

// 全局配置
type Config struct {
	Debug      bool
	LogPath    string
	TmpPath    string
	LockPath   string
	Arch       string
	Version    string
	GithubToken string
}

// OTA信息结构
type OTAInfo struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Date     string `json:"date"`
	MD5      string `json:"md5"`
	Version  string `json:"ver"`
	IP       string `json:"ip"`
	Size     string `json:"size"`
	Arch     string `json:"arch"`
}

// GitHub Release结构
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
		UpdatedAt          string `json:"updated_at"`
		DownloadCount      int    `json:"download_count"`
	} `json:"assets"`
}

// 主应用结构
type OTAApp struct {
	config     *Config
	logger     *logrus.Logger
	fileLocks  map[string]*sync.Mutex
	statusLock sync.RWMutex
	downloadPID int
	cancelChan  chan struct{}
}

func NewOTAApp(cfg *Config) *OTAApp {
	app := &OTAApp{
		config:    cfg,
		fileLocks: make(map[string]*sync.Mutex),
		cancelChan: make(chan struct{}),
	}
	app.initLogger()
	return app
}

func (app *OTAApp) initLogger() {
	app.logger = logrus.New()
	if app.config.Debug {
		app.logger.SetLevel(logrus.DebugLevel)
	}
	
	// 创建日志目录
	os.MkdirAll(filepath.Dir(app.config.LogPath), 0755)
	
	// 文件输出
	file, err := os.OpenFile(app.config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		app.logger.SetOutput(file)
	} else {
		app.logger.SetOutput(os.Stdout)
	}
	
	// 设置格式
	app.logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

func (app *OTAApp) log(level, msg string) {
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] [ota] %s", timestamp, msg)
	
	switch level {
	case "DEBUG":
		app.logger.Debug(msg)
	case "INFO":
		app.logger.Info(msg)
	case "WARN":
		app.logger.Warn(msg)
	case "ERROR":
		app.logger.Error(msg)
	}
	
	// 同时输出到标准输出用于调试
	if app.config.Debug {
		fmt.Println(logEntry)
	}
}

func (app *OTAApp) getLock(name string) *sync.Mutex {
	app.statusLock.Lock()
	defer app.statusLock.Unlock()
	
	if lock, exists := app.fileLocks[name]; exists {
		return lock
	}
	
	lock := &sync.Mutex{}
	app.fileLocks[name] = lock
	return lock
}

// 系统命令执行
func (app *OTAApp) execCommand(cmd string, args ...string) (string, error) {
	app.log("DEBUG", fmt.Sprintf("执行命令: %s %v", cmd, args))
	
	output, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		app.log("ERROR", fmt.Sprintf("命令执行失败: %v, 输出: %s", err, output))
		return "", err
	}
	
	return strings.TrimSpace(string(output)), nil
}

// 读取系统信息
func (app *OTAApp) readOSRelease() (map[string]string, error) {
	releaseInfo := make(map[string]string)
	
	// 读取/etc/os-release
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := strings.Trim(parts[1], `"`)
				releaseInfo[key] = value
			}
		}
	}
	
	return releaseInfo, nil
}

// 初始化Hosts
func (app *OTAApp) initHosts() error {
	lockFile := "/tmp/.github_hosts_added"
	if _, err := os.Stat(lockFile); err == nil {
		return nil // 已经初始化过
	}
	
	// 读取当前hosts
	hostsData, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return err
	}
	
	// 移除旧的github条目
	lines := strings.Split(string(hostsData), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, "github") {
			newLines = append(newLines, line)
		}
	}
	
	// 添加新的github条目
	ip := "140.82.121.4"
	newLines = append(newLines, fmt.Sprintf("%s github.com", ip))
	newLines = append(newLines, fmt.Sprintf("%s api.github.com", ip))
	
	// 写回文件
	err = os.WriteFile("/etc/hosts", []byte(strings.Join(newLines, "\n")), 0644)
	if err != nil {
		return err
	}
	
	// 创建锁文件
	os.Create(lockFile)
	return nil
}

// 计算MD5
func (app *OTAApp) calculateMD5(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// HTTP客户端
func (app *OTAApp) createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 10,
		},
	}
}

// 下载文件
func (app *OTAApp) downloadFile(url, outputPath string) error {
	app.log("INFO", fmt.Sprintf("开始下载: %s -> %s", url, outputPath))
	
	client := app.createHTTPClient()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	// 设置请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	if app.config.GithubToken != "" {
		req.Header.Set("Authorization", "token "+app.config.GithubToken)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP请求失败: %s", resp.Status)
	}
	
	// 创建输出文件
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	
	// 带进度的下载
	reader := bufio.NewReader(resp.Body)
	buffer := make([]byte, 32*1024)
	totalWritten := 0
	
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			written, err := outFile.Write(buffer[:n])
			if err != nil {
				return err
			}
			totalWritten += written
			
			// 更新进度
			if app.config.Debug && totalWritten%(1024*1024) == 0 {
				app.log("DEBUG", fmt.Sprintf("已下载: %.2f MB", float64(totalWritten)/(1024*1024)))
			}
		}
		
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	
	app.log("INFO", "下载完成")
	return nil
}

// 读取ezota.json
func (app *OTAApp) readEzotaJSON(filepath string) (*OTAInfo, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	
	var otaMap map[string][]OTAInfo
	if err := json.Unmarshal(data, &otaMap); err != nil {
		return nil, err
	}
	
	// 查找对应架构的信息
	if infos, exists := otaMap[app.config.Arch]; exists && len(infos) > 0 {
		return &infos[0], nil
	}
	
	return nil, errors.New("未找到对应架构的OTA信息")
}

// 获取GitHub发布信息
func (app *OTAApp) getGitHubReleases() ([]GitHubRelease, error) {
	cacheFile := filepath.Join(app.config.TmpPath, "ota_cache_releases.json")
	
	// 检查缓存
	if info, err := os.Stat(cacheFile); err == nil {
		if time.Since(info.ModTime()) < 5*time.Minute {
			app.log("DEBUG", "使用缓存的GitHub发布信息")
			data, err := os.ReadFile(cacheFile)
			if err != nil {
				return nil, err
			}
			
			var releases []GitHubRelease
			if err := json.Unmarshal(data, &releases); err != nil {
				return nil, err
			}
			return releases, nil
		}
	}
	
	// 从GitHub API获取
	urls := []string{
		GithubAPI,
		GithubMirror,
	}
	
	if app.config.GithubToken != "" {
		urls = append([]string{"https://api.github.com/repositories/256094735/releases"}, urls...)
	}
	
	var releases []GitHubRelease
	var lastErr error
	
	for _, url := range urls {
		app.log("DEBUG", fmt.Sprintf("尝试从 %s 获取发布信息", url))
		
		client := app.createHTTPClient()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		
		if app.config.GithubToken != "" {
			req.Header.Set("Authorization", "token "+app.config.GithubToken)
		}
		
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}
		
		if err := json.Unmarshal(data, &releases); err != nil {
			lastErr = err
			continue
		}
		
		// 缓存结果
		os.WriteFile(cacheFile, data, 0644)
		app.log("INFO", "成功获取GitHub发布信息")
		return releases, nil
	}
	
	return nil, fmt.Errorf("所有API请求失败: %v", lastErr)
}

// 检查更新
func (app *OTAApp) checkUpdate() (map[string]interface{}, error) {
	app.log("INFO", "开始检查更新")
	
	// 初始化
	if err := app.initHosts(); err != nil {
		app.log("WARN", fmt.Sprintf("初始化hosts失败: %v", err))
	}
	
	// 读取系统信息
	osRelease, err := app.readOSRelease()
	if err != nil {
		return nil, err
	}
	
	currentVer := osRelease["OPENWRT_RELEASE"]
	if currentVer == "" {
		currentVer = "unknown"
	}
	
	// 下载ezota.json
	ezotaURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/ezota.json", 
		GithubRepo, osRelease["EZVER"])
	ezotaPath := filepath.Join(app.config.TmpPath, "ezota.json")
	
	if err := app.downloadFile(ezotaURL, ezotaPath); err != nil {
		return nil, err
	}
	
	// 读取OTA信息
	otaInfo, err := app.readEzotaJSON(ezotaPath)
	if err != nil {
		return nil, err
	}
	
	// 获取GitHub发布信息
	releases, err := app.getGitHubReleases()
	if err != nil {
		app.log("WARN", fmt.Sprintf("获取GitHub发布信息失败: %v", err))
	}
	
	// 处理固件信息
	result := map[string]interface{}{
		"current_version": currentVer,
		"arch":           app.config.Arch,
		"cloud_info": map[string]interface{}{
			"name":    otaInfo.Name,
			"version": otaInfo.Version,
			"date":    otaInfo.Date,
			"size":    otaInfo.Size,
			"ip":      otaInfo.IP,
			"md5":     otaInfo.MD5,
			"url":     otaInfo.URL,
		},
	}
	
	// 从GitHub发布中查找固件
	if releases != nil {
		for _, release := range releases {
			for _, asset := range release.Assets {
				if strings.Contains(asset.Name, app.config.Arch) && 
				   (strings.Contains(asset.Name, osRelease["EZVER"]) || 
				    strings.Contains(asset.Name, "Vip-Super")) {
					
					sizeMB := float64(asset.Size) / (1024 * 1024)
					result["cloud_info"].(map[string]interface{})["download_count"] = asset.DownloadCount
					result["cloud_info"].(map[string]interface{})["size"] = fmt.Sprintf("%.2fMB", sizeMB)
					break
				}
			}
		}
	}
	
	// 检查是否需要更新
	if currentVer == otaInfo.Version {
		result["need_update"] = false
		result["latest"] = true
	} else {
		result["need_update"] = true
		result["latest"] = false
		
		// 下载版本说明文件
		verFileURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/ver.latest", 
			GithubRepo, otaInfo.Version)
		verFilePath := filepath.Join(app.config.TmpPath, "ver.latest")
		
		if err := app.downloadFile(verFileURL, verFilePath); err == nil {
			if data, err := os.ReadFile(verFilePath); err == nil {
				result["changelog"] = string(data)
			}
		}
		
		// 下载页脚文件
		footerURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/ota.footer", 
			GithubRepo, otaInfo.Version)
		footerPath := filepath.Join(app.config.TmpPath, "ota.footer")
		
		if err := app.downloadFile(footerURL, footerPath); err == nil {
			if data, err := os.ReadFile(footerPath); err == nil {
				result["footer"] = string(data)
			}
		}
	}
	
	return result, nil
}

// 下载固件
func (app *OTAApp) downloadFirmware() (int, error) {
	ezotaPath := filepath.Join(app.config.TmpPath, "ezota.json")
	otaInfo, err := app.readEzotaJSON(ezotaPath)
	if err != nil {
		return 0, err
	}
	
	firmwarePath := "/tmp/firmware.img"
	partPath := "/tmp/firmware.img.part"
	progressPath := "/tmp/firmware.img.progress"
	md5Path := "/tmp/firmware.img.md5sum"
	pidPath := filepath.Join(app.config.TmpPath, "download.pid")
	
	// 检查已有文件
	if _, err := os.Stat(firmwarePath); err == nil {
		app.log("INFO", "检查已存在的固件文件")
		
		if md5, err := app.calculateMD5(firmwarePath); err == nil && md5 == otaInfo.MD5 {
			app.log("INFO", "固件文件已存在且MD5校验通过")
			os.WriteFile(md5Path, []byte(otaInfo.MD5), 0644)
			return 0, nil
		}
		
		app.log("INFO", "固件文件校验失败，重新下载")
		os.Remove(firmwarePath)
	}
	
	// 创建进度文件
	os.WriteFile(progressPath, []byte("开始下载...\n"), 0644)
	
	// 启动下载goroutine
	ctx, cancel := context.WithCancel(context.Background())
	app.cancelChan = make(chan struct{})
	
	go func() {
		defer cancel()
		
		select {
		case <-ctx.Done():
			app.log("INFO", "下载被取消")
			os.WriteFile(progressPath, []byte("Canceled!\n"), 0644)
			return
		case <-app.cancelChan:
			app.log("INFO", "收到取消信号")
			os.WriteFile(progressPath, []byte("Canceled!\n"), 0644)
			return
		default:
			// 继续下载
		}
		
		// 下载文件
		if err := app.downloadFileWithProgress(otaInfo.URL, partPath, progressPath); err != nil {
			app.log("ERROR", fmt.Sprintf("下载失败: %v", err))
			os.WriteFile(progressPath, []byte(fmt.Sprintf("下载失败: %v\n", err)), 0644)
			return
		}
		
		// 校验MD5
		app.log("INFO", "校验下载的文件")
		os.WriteFile(progressPath, []byte("校验文件...\n"), 0644)
		
		if md5, err := app.calculateMD5(partPath); err != nil {
			app.log("ERROR", fmt.Sprintf("计算MD5失败: %v", err))
			os.WriteFile(progressPath, []byte("Checksum failed!\n"), 0644)
			return
		} else if md5 != otaInfo.MD5 {
			app.log("ERROR", fmt.Sprintf("MD5校验失败: 期望 %s, 实际 %s", otaInfo.MD5, md5))
			os.WriteFile(progressPath, []byte("Checksum failed!\n"), 0644)
			return
		}
		
		// 重命名文件
		if err := os.Rename(partPath, firmwarePath); err != nil {
			app.log("ERROR", fmt.Sprintf("重命名文件失败: %v", err))
			return
		}
		
		// 写入MD5文件
		if err := os.WriteFile(md5Path, []byte(otaInfo.MD5), 0644); err != nil {
			app.log("ERROR", fmt.Sprintf("写入MD5文件失败: %v", err))
			return
		}
		
		app.log("INFO", "下载完成")
		os.Remove(progressPath)
		os.Remove(partPath)
	}()
	
	// 记录PID
	pid := os.Getpid()
	os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", pid)), 0644)
	app.downloadPID = pid
	
	return pid, nil
}

func (app *OTAApp) downloadFileWithProgress(url, outputPath, progressPath string) error {
	client := app.createHTTPClient()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP请求失败: %s", resp.Status)
	}
	
	totalSize := resp.ContentLength
	downloaded := int64(0)
	
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	
	buf := make([]byte, 32*1024)
	lastUpdate := time.Now()
	
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, err := outFile.Write(buf[:n]); err != nil {
				return err
			}
			
			downloaded += int64(n)
			
			// 更新进度（每秒最多更新一次）
			if time.Since(lastUpdate) > time.Second {
				progress := ""
				if totalSize > 0 {
					percent := float64(downloaded) / float64(totalSize) * 100
					progress = fmt.Sprintf("#=#=# %.1f%%\n", percent)
				} else {
					progress = fmt.Sprintf("#=#=# 已下载: %.2f MB\n", float64(downloaded)/(1024*1024))
				}
				
				os.WriteFile(progressPath, []byte(progress), 0644)
				lastUpdate = time.Now()
			}
		}
		
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	
	return nil
}

// 检查下载进度
func (app *OTAApp) checkProgress() (string, error) {
	progressPath := "/tmp/firmware.img.progress"
	md5Path := "/tmp/firmware.img.md5sum"
	ezotaPath := filepath.Join(app.config.TmpPath, "ezota.json")
	
	// 检查是否已完成
	if _, err := os.Stat(md5Path); err == nil {
		otaInfo, err := app.readEzotaJSON(ezotaPath)
		if err == nil {
			if data, err := os.ReadFile(md5Path); err == nil {
				if strings.TrimSpace(string(data)) == otaInfo.MD5 {
					return "completed", nil
				}
			}
		}
	}
	
	// 检查进度文件
	if _, err := os.Stat(progressPath); os.IsNotExist(err) {
		return "not_started", errors.New("下载未开始")
	}
	
	data, err := os.ReadFile(progressPath)
	if err != nil {
		return "error", err
	}
	
	content := string(data)
	if strings.Contains(content, "Canceled!") {
		return "canceled", nil
	}
	
	if strings.Contains(content, "Checksum failed!") {
		return "checksum_failed", errors.New("校验失败")
	}
	
	// 获取最后一行进度
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) > 0 {
		return lines[len(lines)-1], nil
	}
	
	return "downloading", nil
}

// 取消下载
func (app *OTAApp) cancelDownload() error {
	pidPath := filepath.Join(app.config.TmpPath, "download.pid")
	
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		return errors.New("没有正在进行的下载")
	}
	
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	
	// 发送取消信号
	if app.cancelChan != nil {
		close(app.cancelChan)
	}
	
	// 尝试终止进程
	process, err := os.FindProcess(pid)
	if err == nil {
		process.Signal(syscall.SIGTERM)
		time.Sleep(100 * time.Millisecond)
		process.Signal(syscall.SIGKILL)
	}
	
	// 清理文件
	os.Remove("/tmp/firmware.img.part")
	os.Remove(pidPath)
	
	app.log("INFO", "下载已取消")
	return nil
}

// 清理缓存
func (app *OTAApp) clearCache() error {
	app.log("INFO", "开始清理缓存")
	
	// 清理临时目录
	if err := filepath.Walk(app.config.TmpPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && time.Since(info.ModTime()) > 6*time.Hour {
			os.Remove(path)
			app.log("DEBUG", fmt.Sprintf("删除旧文件: %s", path))
		}
		
		return nil
	}); err != nil {
		return err
	}
	
	// 清理/tmp目录
	if err := filepath.Walk("/tmp", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasPrefix(info.Name(), "firmware.img") {
			if time.Since(info.ModTime()) > 6*time.Hour {
				os.Remove(path)
				app.log("DEBUG", fmt.Sprintf("删除旧固件文件: %s", path))
			}
		}
		
		return nil
	}); err != nil {
		return err
	}
	
	app.log("INFO", "缓存清理完成")
	return nil
}

// 运行命令
func (app *OTAApp) runCommand(action string, args []string) (interface{}, error) {
	switch action {
	case "check":
		return app.checkUpdate()
		
	case "download":
		pid, err := app.downloadFirmware()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"pid":     pid,
			"message": "下载已开始",
		}, nil
		
	case "progress":
		status, err := app.checkProgress()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"status":  status,
			"message": status,
		}, nil
		
	case "cancel":
		err := app.cancelDownload()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"message": "下载已取消",
		}, nil
		
	case "clear":
		err := app.clearCache()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"message": "缓存清理完成",
		}, nil
		
	default:
		return nil, fmt.Errorf("未知命令: %s", action)
	}
}

// 输出帮助信息
func printUsage() {
	fmt.Println(`OpenWrt OTA 升级工具 - Go 版本

使用方法: ota <命令> [参数]

命令:
  check     检查固件更新
  download  下载最新固件
  progress  查看下载进度
  cancel    取消下载
  clear     清理缓存

参数:
  --debug   启用调试模式
  --help    显示此帮助信息

示例:
  ota check
  ota download
  ota progress`)
}

func main() {
	// 解析命令行参数
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	
	action := os.Args[1]
	
	// 初始化配置
	cfg := &Config{
		Debug:    os.Getenv("DEBUG") == "1",
		LogPath:  DefaultLogFile,
		TmpPath:  DefaultTmpDir,
		LockPath: DefaultLockDir,
	}
	
	// 读取系统架构
	if arch := os.Getenv("OPENWRT_ARCH"); arch != "" {
		cfg.Arch = arch
	} else {
		// 尝试自动检测
		if output, err := exec.Command("uname", "-m").Output(); err == nil {
			cfg.Arch = strings.TrimSpace(string(output))
		} else {
			cfg.Arch = "unknown"
		}
	}
	
	// 读取GitHub Token
	tokenFile := "/etc/ezgithub"
	if _, err := os.Stat(tokenFile); err == nil {
		if data, err := os.ReadFile(tokenFile); err == nil {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err == nil {
				cfg.GithubToken = string(decoded)
			}
		}
	}
	
	// 创建应用
	app := NewOTAApp(cfg)
	
	// 确保临时目录存在
	os.MkdirAll(cfg.TmpPath, 0755)
	os.MkdirAll(cfg.LockPath, 0755)
	
	// 执行命令
	result, err := app.runCommand(action, os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	
	// 输出结果
	if result != nil {
		if data, err := json.MarshalIndent(result, "", "  "); err == nil {
			fmt.Println(string(data))
		}
	}
}
