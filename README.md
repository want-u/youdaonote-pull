# youdaonote-pull

<!--Becauce basically only Chinese users use "Youdao Note", so this project only provides Chinese README.md-->

## 功能 <!--Feature-->

- 仅针对有道云笔记中的md文件
- 将有道云本地的md文件，按照笔记目录结构备份一份新的文件夹，方便同步上传github等

## 使用步骤 <!--用法 Usage-->

<!--针对普通用户-->

### 一、导出前的准备工作

#### 1、安装  [Git](https://git-scm.com/downloads)、clone 项目

- 可根据 [廖雪峰 Git 教程](https://www.liaoxuefeng.com/wiki/896043488029600/896067074338496) 安装 Git，测试是否安装成功

```sh
git --version
```

- 打开命令行软件，如 Terminal (macOS)、PowerShell (Windows)，clone 项目，里面包含脚本

```shell
pwd
git clone https://github.com/DeppWang/youdaonote-pull.git
cd youdaonote-pull
```

#### 2、安装 [Python3](https://www.python.org/downloads/)、安装依赖模块（包）

- 可根据 [廖雪峰 Python 教程](https://www.liaoxuefeng.com/wiki/1016959663602400/1016959856222624) 安装 Python3，测试是否安装成功

```shell
python3 --version  # macOS/Linux
python --version   # Windows
```

- 安装依赖包

```shell
# macOS
sudo easy_install pip3      # 安装 Python3 Package Installer
sudo pip3 install requests     #  安装 requests
```
```shell
# Windows
pip install requests  

# 有问题可参考 https://www.liaoxuefeng.com/wiki/1016959663602400/1017493741106496
```
#### 3、设置脚本参数配置文件 config.json

```json
{
    "username": "your_youdaonote_username",
    "password": "your_youdaonote_password",
    "local_dir": "",
    "ydnote_dir": [],
    "local_md": ""
}
```

* username：**必填**，你的有道云笔记用户名
* password：**必填**，你的有道云笔记密码
* local_dir：选填，本地存放导出文件的文件夹，不填则默认为当前文件夹
* ydnote_dir：选填，列表格式，有道云笔记指定导出文件夹名，不填则导出所有文件，如：  "ydnote_dir": ["XiaoMi", "Github"]
* local_md：,有道云本地保存文件夹，如：  "local_md": "D:\\有道云\\luoxian1011@163.com"
* 提示：脚本单纯本地运行，不用担心你的账号密码泄露；建议使用 [Sublime](https://www.sublimetext.com/3) 编辑 config.json（避免编码格式错误）

示例：

- macOS

```json
{
    "username": "deppwangtest@163.com",
    "password": "12345678",
    "local_dir": "/Users/yanjie/Documents/youdaonote-pull/test",
    "ydnote_dir": "",
    "local_md": "D:\\有道云\\luoxian1011@163.com"
}
```

- Windows

```json
{
    "username": "deppwangtest@163.com",
    "password": "12345678",
    "local_dir": "D:/Documents/youdaonote-pull/test",
    "ydnote_dir": "",
    "local_md": "D:\\有道云\\luoxian1011@163.com"
}
```

###  二、运行导出脚本

```shell
python3 pull.py  # macOS/Linux
python pull.py   # Windows
```

效果：

![2020-06-23-145839](https://deppwang.oss-cn-beijing.aliyuncs.com/blog/2020-08-04-073242.png)

### 三、多次导出

多次导出时，同样使用以下命令：

```shell
python3 pull.py  # macOS/Linux
python pull.py   # Windows
```

根据有道云笔记文件最后修改时间是否大于本地文件最后修改时间来判断是否需要更新。再次导出时，只会导出有道云笔记上次导出后新增、修改或未导出的笔记，不会覆盖本地已经修改的文件。**但有道云笔记和本地不要同时修改同一个文件，这样可能会导致本地修改丢失**！

更新时，会重新下载文件并覆盖原文件，图片也会重新下载。

<!--只会导出本地不存在，或更新时间大于本地的文件-->

## 注意事项  <!--Tips 使用提示-->

1. 如果你自己修改脚本，注意不要将 config.json 文件 push 到 GitHub（里面有账号密码）
2. 如果你不是开发者，可能对上面的命令行操作有所陌生，建议按步骤慢慢操作一遍。后续我会根据需求看是否应该提供网页下载
3. 请确认代码是否为最新，有问题请提交 [issue](https://github.com/DeppWang/youdaonote-pull/issues?q=is%3Aissue+is%3Aclosed)
   ```bash
   git pull origin master  # 更新代码
   ```

<!--在 CentOS 环境下，由于命令行环境不能直接显示中文，所以会出现 UnicodeEncodeError-->

<!--Windows 常见问题-->

<!--Git Bash、Windows Terminal Preview 无法执行 `git --version` / `python --version`-->
<!--使用 PowerShell-->
<!--PowerShell 命令行乱码，不显示中文-->
<!--[设置语言](https://stackoverflow.com/a/57134096/6953079)，重启，使用 Windows Terminal Preview-->

<!--后续开发计划  TODO-->

<!--将 .note 文件转换为 Markdown 文件-->
<!--解决有道云图床图片不能显示问题，实现方式为默认下载到本地，使用本地图片链接，也可上传到 SM.MS 图床-->
<!--首次导出使用账号密码登录，再次导出时使用 Cookie 登录（Cookie 保存在 cookies.json 中），避免频繁操作时因为需要输入验证码导致登录不上的情况-->

<!--并发执行以加快速度-->
<!--针对非开发者用户，提供网页输入账号密码直接下载所有笔记压缩包的方式-->
<!--优化如果同一目录存在同名的 .md 和 .note 文件，只能保存一个的情况-->
## 原理 <!--Principle-->

正常用户操作时，浏览器（前端）调用服务器（后端）接口，接口返回文件内容由前端渲染显示。原理是[找到有道云笔记的接口](https://depp.wang/2020/06/11/how-to-find-the-api-of-a-website-eg-note-youdao-com)，模拟操作接口，将前端显示改为存放到本地。Xml 转换为 Markdown，借助了 [xml.etree.ElementTreeI](http://docs.python.org/3.7/library/xml.etree.elementtree.html)

## 感谢（参考） <!--Thanks-->

- [YoudaoNoteExport](https://github.com/wesley2012/YoudaoNoteExport)

## 出发点 <!--Starting Point-->

原来一直是有道云笔记的忠实用户，后面接触到了「所见即所得」的 [Typora](https://typora.io/)，有点用不惯有道云笔记了，想着有什么法子能电脑本地文件和有道云笔记同步，这样电脑使用 Typora，手机使用有道云笔记。发现有道云笔记有 [Open API](http://note.youdao.com/open/developguide.html) ，打算利用提供的 API，写两个脚本，一个 pull 所有文件到本地，一个 push 本地文件到云笔记。但 API 太难用了，N 多年没更新了，问客服也没更新的意思，开发到最后发现竟然没有 Markdown 文件的接口，醉了。遂放弃。

现在我使用 Typora + [Dropbox](https://www.dropbox.com/)（有版本历史记录） + [MWeb](https://www.mweb.im/) 实现自动同步笔记和手机查看编辑的功能，很香。

最近给朋友推荐此方式，但发现有道云笔记最新的 Mac 客户端和网页端去除了导出所有笔记的功能！这是什么逻辑，怕用户跑了么。所以在原来 pull 脚本的基础上修改得到此脚本。

## 贡献

欢迎贡献代码，但有几个注意事项：

1. commit 请使用英文
2. 代码注解需要有[中英文空格](https://github.com/sparanoid/chinese-copywriting-guidelines)
3. 请确保通过测试
   - 在 macOS 和 Windows 环境中直接执行 `pull.py` 没有问题（你可以指定下载一个文件夹测试）
   - 在 `test.py` 配置中你的脚本参数（UserDefine），运行测试脚本  `test.py`  没有问题

<!--## 打赏-->

<!--请作者吃包辣条？-->

<!--支付宝--> 
<!--微信--> 
<!--![IMG_2549](https://deppwang.oss-cn-beijing.aliyuncs.com/blog/2020-08-16-142007.jpg)-->
<!--![IMG_2550](https://deppwang.oss-cn-beijing.aliyuncs.com/blog/2020-08-16-142705.jpg)-->

<!--## 同一文件夹重名问题-->

<!--网页版有道云笔记本身将所有笔记显示，不存在-->

<!--默认将 note 保存为 md，再次出现同名时，会判断是否需要更新，需要则更新，不需要则跳过-->

<!--存在同名 note 和 md 时，note 先保存为 md，后面 md 如果修改时间晚，将覆盖 note，如果早，将跳过。-->

<!--只能将原来的 note 做个标记，知道是 note，可以直接 **note.md，但不美观-->

<!--设置一个 map，保存当前文件夹下的所有文件，判断 map 中是否重名，记录重名 key，遍历时判断，如果等于 key，笔记名称加上 flag 区分-->



![Profile views](https://gpvc.arturio.dev/youdaonote-pull)
