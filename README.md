# rocnet
a simple network server framework
C语言编写的多线程网络库


ROC API
```
int roc_init(const char *log_path, int log_level);
```
功能 :初始化环境(日志环境, 线程池环境等)

参数 :

 *  **log_path (const char \*)**
    日志记录的文件的路径

 *  **log_level (int)**
    日志记录的最高级别

返回值 : 成功返回0, 失败返回-1

```
roc_svr *roc_svr_new(int port);
```
功能 :创建并填充一个server数据结构(不启动)

参数 :

 *  **port (int)**
    server监听的端口

返回值 : 成功返回所创建的server的指针, 失败返回NULL

```
int roc_svr_use(roc_svr *svr, char *plugin_path);
```
功能 :为server添加中间件

参数 :

 *  **svr (roc_svr \*)**
    目标server

 *  **plugin_path (char \*)**
    中间件的路径

返回值 : 成功返回0, 失败返回-1

```
void roc_svr_on(roc_svr *svr, int evt_type, roc_handle_func_link *handler);
```
功能 :server监听事件

参数 :

 *  **svr (roc_svr \*)**
    目标server

 *  **evt_type (int)**
    事件类型,宏定义在roc_evt.h

 *  **handler (roc_handle_func_link \*)**
    事件处理器

返回值 : void

```
int roc_svr_start(roc_svr *svr);
```
功能 :启动server

参数 :

 *  **svr (roc_svr \*)**
    目标server

返回值 : 成功返回0, 失败返回-1

```
void roc_link_on(roc_link *link, int evt_type, roc_handle_func_link *handler);
```
功能 :server监听事件

参数 :

 *  **link (roc_link \*)**
    目标连接

 *  **evt_type (int)**
    事件类型,宏定义在roc_evt.h

 *  **handler (roc_handle_func_link \*)**
    事件处理器

返回值 : void
