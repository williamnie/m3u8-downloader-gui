package main

import (
	"crypto/aes"
	"crypto/cipher"
	"embed"
	"flag"
	"fmt"
	"log"
	"m3u8-downloader/parse"
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

// 定义请求参数的结构体
type DownloadRequest struct {
	URL     string `json:"u" binding:"required"`
	NFlag   *int   `json:"n"`
	HTFlag  string `json:"ht"`
	OFlag   string `json:"o" binding:"required"`
	CFlag   string `json:"c"`
	RFlag   *bool  `json:"r"`
	SFlag   int    `json:"s"`
	SPFlag  string `json:"sp"`
	Referer string `json:"referer"`
	Proxy   string `json:"proxy"`
	Sync    bool   `json:"sync"`
}

type UpdataTask struct {
	ID  int    `json:"id" binding:"required"`
	URL string `json:"url" binding:"required"`
}

// Task represents a download task
type Task struct {
	ID         int                     `json:"id"`
	URL        string                  `json:"url"`
	Status     string                  `json:"status"`
	TotalTs    int                     `json:"total_ts"`
	Message    string                  `json:"message"`
	Completed  float32                 `json:"completed"`
	TotalTime  float64                 `json:"totalTime"`
	MasterList []*parse.MasterPlaylist `json:"master_list"`
	TaskInfo   DownloadRequest         `json:"taskInfo"`
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
					if e.Field() == "URL" && e.Tag() == "required" {
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
		if !strings.HasPrefix(req.URL, "http") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "下载链接格式错误"})
			return
		}
		if req.Proxy != "" {
			proxyURL, err := url.Parse(req.Proxy) // Proxy URL
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "代理地址错误"})
				return
			}
			ro.Proxies = map[string]*url.URL{proxyURL.Scheme: proxyURL}
		} else if req.Proxy == "" && ro.Proxies != nil {
			ro.Proxies = nil
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
			URL:       req.URL,
			Status:    "下载中",
			TotalTs:   0, // 假设总共有 0 个 ts 文件
			Completed: 0,
			TotalTime: 0,
			TaskInfo:  req,
		}
		tasks = append(tasks, newTask)
		taskMux.Unlock()
		if req.Sync {
			Run(newTask.ID, newTask.TaskInfo.URL,
				*(newTask.TaskInfo.NFlag), newTask.TaskInfo.HTFlag,
				newTask.TaskInfo.OFlag, newTask.TaskInfo.CFlag,
				*(newTask.TaskInfo.RFlag), newTask.TaskInfo.SFlag,
				newTask.TaskInfo.SPFlag, newTask.TaskInfo.Referer,
			)
		} else {
			go Run(newTask.ID, newTask.TaskInfo.URL,
				*(newTask.TaskInfo.NFlag), newTask.TaskInfo.HTFlag,
				newTask.TaskInfo.OFlag, newTask.TaskInfo.CFlag,
				*(newTask.TaskInfo.RFlag), newTask.TaskInfo.SFlag,
				newTask.TaskInfo.SPFlag, newTask.TaskInfo.Referer,
			)
		}

		c.JSON(http.StatusOK, gin.H{"status": "success", "taskID": newTask.ID})
	})

	r.POST("/updata", func(c *gin.Context) {
		var req UpdataTask
		if err := c.ShouldBindJSON(&req); err != nil {
			if errs, ok := err.(validator.ValidationErrors); ok {
				// 遍历错误字段, 进行判断
				for _, e := range errs {
					if e.Field() == "URL" && e.Tag() == "required" {
						c.JSON(http.StatusBadRequest, gin.H{"error": "缺少下载链接"})
						return
					}
					if e.Field() == "ID" && e.Tag() == "required" {
						c.JSON(http.StatusBadRequest, gin.H{"error": "缺少对应的taskID"})
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
		if !strings.HasPrefix(req.URL, "http") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "下载链接格式错误"})
			return
		}

		taskMux.Lock()
		var newTask Task
		for i := range tasks {
			if tasks[i].ID == req.ID {
				tasks[i].Status = "下载中"
				tasks[i].URL = req.URL
				tasks[i].TotalTs = 0
				tasks[i].Completed = 0
				tasks[i].TotalTime = 0
				newTask = tasks[i]
				break
			}
		}
		taskMux.Unlock()
		fmt.Println("newTask:", newTask)
		go Run(newTask.ID, newTask.URL,
			*(newTask.TaskInfo.NFlag), newTask.TaskInfo.HTFlag,
			newTask.TaskInfo.OFlag, newTask.TaskInfo.CFlag,
			*(newTask.TaskInfo.RFlag), newTask.TaskInfo.SFlag,
			newTask.TaskInfo.SPFlag, newTask.TaskInfo.Referer,
		)
		c.JSON(http.StatusOK, gin.H{"status": "success", "taskID": newTask.ID})
	})

	r.GET("/tasks", func(c *gin.Context) {
		c.JSON(http.StatusOK, tasks)
	})

	r.GET("/clearTasks", func(c *gin.Context) {
		// 找到tasks中所有已经完成的任务，清除掉
		taskMux.Lock()
		var newTasks []Task
		for i := range tasks {
			if tasks[i].Status != "完成" {
				newTasks = append(newTasks, tasks[i])
			}
		}
		tasks = newTasks
		taskMux.Unlock()
		c.JSON(http.StatusOK, gin.H{"status": "success"})
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

func Run(taskID int, m3u8Url string, maxGoroutines int, hostType string, movieName string, cookie string, autoClearFlag bool, insecure int, savePath string, referer string) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	now := time.Now()
	if referer != "" {
		ro.Headers["Referer"] = referer
	} else {
		ro.Headers["Referer"] = getHost(m3u8Url, "v2")
	}
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
	m3u8Body, err := getM3u8Body(m3u8Url, hostType)
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
	// 如果有masterplaylist则说明是有多层级的m3u8地址,返回让用户选择
	if m3u8Body.MasterPlaylist != nil {
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "暂停"
				tasks[i].Message = "当前链接内有多个m3u8地址，请选择一个下载"
				tasks[i].MasterList = m3u8Body.MasterPlaylist
				break
			}
		}
		return
	}
	// 将 keys 转换为 JSON 格式并打印出来

	// 当存在keys时，则去请求加密数据
	if len(m3u8Body.Keys) > 0 {
		getM3u8Key(m3u8Body)
	}

	// 如果segmentlist为空，则表示没解析到ts，直接报错,不为空的则更新task
	if len(m3u8Body.Segments) == 0 {
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "失败"
				tasks[i].TotalTs = 0
				tasks[i].Message = "未解析到ts切片"
				break
			}
		}
		return
	} else {
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "下载中"
				tasks[i].TotalTs = len(m3u8Body.Segments)
				break
			}
		}
	}

	// 3、下载ts文件到download_dir
	downloader(taskID, m3u8Body.Segments, maxGoroutines, download_dir, m3u8Body.Keys)
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
	mp4Path, err := parse.MergeTs(download_dir)
	if err != nil {
		for i := range tasks {
			if tasks[i].ID == taskID {
				tasks[i].Status = "失败"
				tasks[i].TotalTime = time.Since(now).Seconds()
				tasks[i].Message = fmt.Sprintf("合并切片失败: %s", err.Error())
				break
			}
		}
	}
	if autoClearFlag {
		//自动清除ts文件目录
		os.RemoveAll(download_dir)
	}

	//5、输出下载视频信息
	for i := range tasks {
		if tasks[i].ID == taskID {
			tasks[i].Status = "完成"
			tasks[i].Completed = 1
			tasks[i].TotalTime = time.Since(now).Seconds()
			tasks[i].Message = "下载成功：" + mp4Path
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
func getM3u8Body(Url string, ht string) (*parse.M3u8, error) {
	r, err := grequests.Get(Url, ro)
	if err != nil {
		return nil, err
	}
	defer r.Close() // 确保关闭响应体
	host := getHost(Url, ht)
	bodyString := r.String()
	lines := strings.Split(bodyString, "\n")
	if lines[0] != "#EXTM3U" {
		return nil, fmt.Errorf(r.String())
	}

	m3u8, parseErr := parse.Parse(lines, host)
	return m3u8, parseErr
}

// 获取m3u8加密的密钥
func getM3u8Key(m3u8Body *parse.M3u8) {
	// 循环Keys，根据里面的URI，发送请求，如果成功，则更新到KeyBody字段
	for _, key := range m3u8Body.Keys {
		if key.Method != "" && key.Method != parse.CryptMethodNONE {
			res, err := grequests.Get(key.URI, ro) // 直接使用key.URI
			checkErr(err)
			if res.StatusCode == 200 {
				key.KeyBody = res.String()
			}
		}
	}
}

// downloader m3u8 下载器
func downloader(taskID int, tsList []*parse.Segment, maxGoroutines int, downloadDir string, keys map[int]*parse.Key) {
	retry := 5 //单个 ts 下载重试次数
	var wg sync.WaitGroup
	limiter := make(chan struct{}, maxGoroutines) //chan struct 内存占用 0 bool 占用 1
	tsLen := len(tsList)
	downloadCount := 0
	for _, ts := range tsList {
		wg.Add(1)
		limiter <- struct{}{}
		go func(ts *parse.Segment, downloadDir string, key *parse.Key, retryies int) {
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
		}(ts, downloadDir, keys[ts.KeyIndex], retry)
	}
	wg.Wait()
}

// 下载ts文件
func downloadTsFile(ts *parse.Segment, download_dir string, key *parse.Key, retries int) {
	defer func() {
		if r := recover(); r != nil {
			downloadTsFile(ts, download_dir, key, retries-1)
		}
	}()
	curr_path_file := fmt.Sprintf("%s/%s", download_dir, ts.Name)
	if isExist, _ := pathExists(curr_path_file); isExist {
		return
	}
	res, err := grequests.Get(ts.URI, ro)
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
	if key != nil && key.Method != parse.CryptMethodNONE && key.Method != "" {
		//解密 ts 文件，算法：aes 128 cbc pack5
		origData, err = AesDecrypt(origData, []byte(key.KeyBody), []byte(key.IV))
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

func checkTsDownDir(dir string) bool {
	if isExist, _ := pathExists(filepath.Join(dir, fmt.Sprintf(TS_NAME_TEMPLATE, 0))); !isExist {
		return true
	}
	return false
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

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesDecrypt(crypted, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(iv) == 0 {
		iv = key
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func checkErr(e error) {
	if e != nil {
		logger.Panic(e)
	}
}
