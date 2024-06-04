package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/levigross/grequests"
)

const (
	// HEAD_TIMEOUT 请求头超时时间
	HEAD_TIMEOUT = 5 * time.Second
	// TS_NAME_TEMPLATE ts视频片段命名规则
	TS_NAME_TEMPLATE = "%05d.ts"
)

//go:embed index.html

var indexHTML embed.FS

var (
	port   = flag.String("port", "10000", "请输入端口号")
	logger *log.Logger
	ro     = &grequests.RequestOptions{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36",
		RequestTimeout: HEAD_TIMEOUT,
		Headers: map[string]string{
			"Connection":      "keep-alive",
			"Accept":          "*/*",
			"Accept-Encoding": "*",
			"Accept-Language": "zh-CN,zh;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
		},
	}
)

// TsInfo 用于保存 ts 文件的下载地址和文件名
type TsInfo struct {
	Name string
	Url  string
}

// 定义请求参数的结构体
type DownloadRequest struct {
	URLFlag string `json:"u" binding:"required"`
	NFlag   *int   `json:"n"`
	HTFlag  string `json:"ht"`
	OFlag   string `json:"o" binding:"required"`
	CFlag   string `json:"c"`
	RFlag   *bool  `json:"r"`
	SFlag   int    `json:"s"`
	SPFlag  string `json:"sp"`
}

// Task represents a download task
type Task struct {
	ID        int     `json:"id"`
	URL       string  `json:"url"`
	Status    string  `json:"status"`
	TotalTs   int     `json:"total_ts"`
	Message   string  `json:"message"`
	Completed float32 `json:"completed"`
	TotalTime float64 `json:"totalTime"`
}

var (
	tasks   []Task
	taskID  int
	taskMux sync.Mutex
)

func main() {
	flag.Parse()
	r := gin.Default()
	r.POST("/download", func(c *gin.Context) {
		var req DownloadRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			if errs, ok := err.(validator.ValidationErrors); ok {
				// 遍历错误字段, 进行判断
				for _, e := range errs {
					if e.Field() == "URLFlag" && e.Tag() == "required" {
						c.JSON(http.StatusBadRequest, gin.H{"error": "缺少下载链接"})
						return
					}
					if e.Field() == "OFlag" && e.Tag() == "required" {
						c.JSON(http.StatusBadRequest, gin.H{"error": "请填写文件名"})
						return
					}
				}
			} else {
				// 如果不是验证类型的错误，则原样返回
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		}
		// 校验 u 参数
		if !strings.HasPrefix(req.URLFlag, "http") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "下载链接格式错误"})
			return
		}

		if req.HTFlag == "" {
			req.HTFlag = "v1"
		}

		var defaultRFlag bool = true
		if req.RFlag == nil {
			req.RFlag = &defaultRFlag
		}
		var defaultNFlag int = 24
		if req.NFlag == nil {
			req.NFlag = &defaultNFlag
		}

		taskMux.Lock()
		taskID++
		newTask := Task{
			ID:        taskID,
			URL:       req.URLFlag,
			Status:    "下载中",
			TotalTs:   0, // 假设总共有 0 个 ts 文件
			Completed: 0,
			TotalTime: 0,
		}
		tasks = append(tasks, newTask)
		taskMux.Unlock()
		go Run(newTask.ID, req.URLFlag, *(req.NFlag), req.HTFlag, req.OFlag, req.CFlag, *(req.RFlag), req.SFlag, req.SPFlag)
		c.JSON(http.StatusOK, gin.H{"status": "success", "taskID": newTask.ID})
	})

	r.GET("/tasks", func(c *gin.Context) {
		c.JSON(http.StatusOK, tasks)
	})

	r.GET("/", func(c *gin.Context) {
		// 直接发送 index.html 文件
		content, _ := indexHTML.ReadFile("index.html")
		c.Data(http.StatusOK, "text/html; charset=utf-8", content)
	})

	serverPort := ":" + *port
	// 启动服务器并监听指定端口
	if err := r.Run(serverPort); err != nil {
		panic(err)
	}
}

func Run(taskID int, m3u8Url string, maxGoroutines int, hostType string, movieName string, cookie string, autoClearFlag bool, insecure int, savePath string) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	now := time.Now()

	ro.Headers["Referer"] = getHost(m3u8Url, "v2")
	if insecure != 0 {
		ro.InsecureSkipVerify = true
	}
	// http 自定义 cookie
	if cookie != "" {
		ro.Headers["Cookie"] = cookie
	}
	var download_dir string
	pwd, _ := os.Getwd()
	if savePath != "" {
		pwd = savePath
	}
	// 初始化下载ts的目录，后面所有的ts文件会保存在这里
	download_dir = filepath.Join(pwd, movieName)
	if isExist, _ := pathExists(download_dir); !isExist {
		os.MkdirAll(download_dir, os.ModePerm)
	}

	// 2、解析m3u8
	m3u8Host, m3u8Body, err := getM3u8Body(m3u8Url, hostType)
	if err != nil {
		errorMsg := fmt.Sprintf("获取不到m3u8内容: %v", err)
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "失败"
				tasks[i].Message = errorMsg
				break
			}
		}

		return
	}
	ts_key := getM3u8Key(m3u8Host, m3u8Body)
	if ts_key != "" {
		fmt.Printf("待解密 ts 文件 key : %s \n", ts_key)
	}
	ts_list := getTsList(m3u8Host, m3u8Body)
	if len(ts_list) == 0 {
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "失败"
				tasks[i].TotalTs = len(ts_list)
				tasks[i].Message = "未解析到ts切片"
				break
			}
		}
		return
	}
	for i := range tasks {
		if tasks[i].ID == taskID {
			tasks[i].Status = "下载中"
			tasks[i].TotalTs = len(ts_list)
			break
		}
	}

	// 3、下载ts文件到download_dir
	downloader(taskID, ts_list, maxGoroutines, download_dir, ts_key)
	if ok := checkTsDownDir(download_dir); !ok {
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "失败"
				tasks[i].Message = "请检查url地址有效性"
				break
			}
		}
		return
	}

	// 4、合并ts切割文件成mp4文件
	mergeTs(download_dir)
	if autoClearFlag {
		//自动清除ts文件目录
		os.RemoveAll(download_dir)
	}

	//5、输出下载视频信息
	for i := range tasks {
		if tasks[i].ID == taskID {
			tasks[i].Status = "完成"
			tasks[i].Completed = 1
			tasks[i].TotalTime = time.Now().Sub(now).Seconds()
			break
		}
	}
}

// 获取m3u8地址的host
func getHost(Url, ht string) (host string) {
	u, err := url.Parse(Url)
	checkErr(err)
	switch ht {
	case "v1":
		host = u.Scheme + "://" + u.Host + filepath.Dir(u.EscapedPath())
	case "v2":
		host = u.Scheme + "://" + u.Host
	}
	return
}

// 获取m3u8地址的内容体
func getM3u8Body(Url string, ht string) (string, string, error) {
	r, err := grequests.Get(Url, ro)
	if err != nil {
		return "", "", err
	}
	host := getHost(Url, ht)
	bodyString := r.String()
	lines := strings.Split(bodyString, "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" && strings.HasSuffix(line, "m3u8") {
			//嵌套格式的m3u8,
			fmt.Print("real==", host+"/"+line)
			return getM3u8Body(host+"/"+line, ht)
		}
	}
	return host, r.String(), nil
}

// 获取m3u8加密的密钥
func getM3u8Key(host, html string) (key string) {
	lines := strings.Split(html, "\n")
	key = ""
	for _, line := range lines {
		if strings.Contains(line, "#EXT-X-KEY") {
			uri_pos := strings.Index(line, "URI")
			quotation_mark_pos := strings.LastIndex(line, "\"")
			key_url := strings.Split(line[uri_pos:quotation_mark_pos], "\"")[1]
			if !strings.Contains(line, "http") {
				key_url = fmt.Sprintf("%s/%s", host, key_url)
			}
			res, err := grequests.Get(key_url, ro)
			checkErr(err)
			if res.StatusCode == 200 {
				key = res.String()
			}
		}
	}
	return
}

func getTsList(host, body string) (tsList []TsInfo) {
	lines := strings.Split(body, "\n")
	index := 0
	var ts TsInfo
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" && strings.Contains(line, "ts") {
			//有可能出现的二级嵌套格式的m3u8,请自行转换！
			index++
			if strings.HasPrefix(line, "http") {
				ts = TsInfo{
					Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
					Url:  line,
				}
				tsList = append(tsList, ts)
			} else {
				ts = TsInfo{
					Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
					Url:  fmt.Sprintf("%s/%s", host, line),
				}
				tsList = append(tsList, ts)
			}
		}
	}
	return
}

// 下载ts文件
// @modify: 2020-08-13 修复ts格式SyncByte合并不能播放问题
func downloadTsFile(ts TsInfo, download_dir, key string, retries int) {
	defer func() {
		if r := recover(); r != nil {
			downloadTsFile(ts, download_dir, key, retries-1)
		}
	}()
	curr_path_file := fmt.Sprintf("%s/%s", download_dir, ts.Name)
	if isExist, _ := pathExists(curr_path_file); isExist {
		return
	}
	res, err := grequests.Get(ts.Url, ro)
	if err != nil || !res.Ok {
		if retries > 0 {
			downloadTsFile(ts, download_dir, key, retries-1)
			return
		} else {
			return
		}
	}
	// 校验长度是否合法
	var origData []byte
	origData = res.Bytes()
	contentLen := 0
	contentLenStr := res.Header.Get("Content-Length")
	if contentLenStr != "" {
		contentLen, _ = strconv.Atoi(contentLenStr)
	}
	if len(origData) == 0 || (contentLen > 0 && len(origData) < contentLen) || res.Error != nil {
		downloadTsFile(ts, download_dir, key, retries-1)
		return
	}
	// 解密出视频 ts 源文件
	if key != "" {
		//解密 ts 文件，算法：aes 128 cbc pack5
		origData, err = AesDecrypt(origData, []byte(key))
		if err != nil {
			downloadTsFile(ts, download_dir, key, retries-1)
			return
		}
	}
	// https://en.wikipedia.org/wiki/MPEG_transport_stream
	// Some TS files do not start with SyncByte 0x47, they can not be played after merging,
	// Need to remove the bytes before the SyncByte 0x47(71).
	syncByte := uint8(71) //0x47
	bLen := len(origData)
	for j := 0; j < bLen; j++ {
		if origData[j] == syncByte {
			origData = origData[j:]
			break
		}
	}
	os.WriteFile(curr_path_file, origData, 0666)
}

// downloader m3u8 下载器
func downloader(taskID int, tsList []TsInfo, maxGoroutines int, downloadDir string, key string) {
	retry := 5 //单个 ts 下载重试次数
	var wg sync.WaitGroup
	limiter := make(chan struct{}, maxGoroutines) //chan struct 内存占用 0 bool 占用 1
	tsLen := len(tsList)
	downloadCount := 0
	for _, ts := range tsList {
		wg.Add(1)
		limiter <- struct{}{}
		go func(ts TsInfo, downloadDir, key string, retryies int) {
			defer func() {
				wg.Done()
				<-limiter
			}()
			downloadTsFile(ts, downloadDir, key, retryies)
			downloadCount++
			for i := range tasks {
				if tasks[i].ID == taskID {
					tasks[i].Completed = float32(downloadCount) / float32(tsLen)
					break
				}
			}
			return
		}(ts, downloadDir, key, retry)
	}
	wg.Wait()
}

func checkTsDownDir(dir string) bool {
	if isExist, _ := pathExists(filepath.Join(dir, fmt.Sprintf(TS_NAME_TEMPLATE, 0))); !isExist {
		return true
	}
	return false
}

// 合并ts文件
func mergeTs(downloadDir string) string {
	mvName := downloadDir + ".mp4"
	outMv, _ := os.Create(mvName)
	defer outMv.Close()
	writer := bufio.NewWriter(outMv)
	err := filepath.Walk(downloadDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() || filepath.Ext(path) != ".ts" {
			return nil
		}
		bytes, _ := os.ReadFile(path)
		_, err = writer.Write(bytes)
		return err
	})
	checkErr(err)
	_ = writer.Flush()
	return mvName
}

// ============================== shell相关 ==============================
// 判断文件是否存在
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// ============================== 加解密相关 ==============================

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func checkErr(e error) {
	if e != nil {
		logger.Panic(e)
	}
}
