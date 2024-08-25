# m3u8下载器GUI版本

主要参考以下两个开源项目
[m3u8-downloader](https://github.com/llychao/m3u8-downloader)
[m3u8](https://github.com/oopsguy/m3u8/tree/master)

为了方便放到服务器上跑及其他程序调用，改造成http服务。
支持通过简易页面进行添加任务，支持通过接口供其他服务调用。

![gui](./gui.png)

## 功能介绍

1. 支持下载多层m3u8地址（需要用户手动选择需要下载的分辨率）
2. 支持GUI，有个简单的页面，方便直接添加任务
3. 支持自定义端口，默认启动在10000端口上，如果想自定义端口启动，可在后面加 -port=端口号

## TODO

1. fork下猫爪的项目，改动一下，支持从猫爪一键发送到本下载工具


## 用法

### 源码方式

```bash
自己编译：go build -o main.go
```

### 下载地址

[Release](https://github.com/williamnie/m3u8-downloader-gui/releases)


## 部署说明

linux下可采用systemctl方式启动，项目中提供了m3u8.service作为模板，修改为自己的参数即可

```
[Unit]
Description=My M3U8 Downloader
After=network.target

[Service]
ExecStart=you app path
Environment="GIN_MODE=release"
User=you user name
Group=you user gtoup
Restart=always
RestartSec=3
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

启动命令

```
 systemctl enable m3u8.service
 systemctl start m3u8.service // 启动服务
 systemctl status m3u8.service // 查看状态
```