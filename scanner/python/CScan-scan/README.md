# 使用

## 替换执行文件(masscan&&nmap)
**masscan&&nmap下的可执行文件是在ubuntu下编译的**
- 删除masscan`目录`和nmap`目录`
- 分别执行安装脚本

```shell
sh installMasscan.sh
sh installNmap.sh
```


## 运行扫描
```shell

python main.py -h

 

python main.py -u <ip> -p <port(端口, 默认如下)> -r <rate(masscan的并发率, 默认1000)>

 

默认端口：

    21, 22, 23, 25, 53 ,69, 80, 110, 443, 1080, 1158, 1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001, 8000, 8080, 8081, 9080, 9090

```

## 输出之后结果都写在了 tmp 目录下

 

- Assets.json --- 资产

- SCA.json  --- 服务组件

- Whatweb.json  --- 服务提供组件/应用组件

 

 

# 结果说明

## 资产

```python
{
	"assets": 					# 资产 :·
    ["192.168.1.2", "192.168.1.1"]			#资产ip列表

}

```

 

## 服务组件

> 从扫出的资产结果中，再次扫出资产服务组件

```python
{

    "SCA": [{						#服务组件 : 
        "192.168.1.2": [{				# 资产ip

            "port": "3306",				# 开启的端口

            "name": "mysql"				# 端口对应的服务名

        }]

    }, {

        "192.168.1.1": [{

            "port": "53",

            "name": "domain"

        }, {

            "port": "80",

            "name": "http"

        }, {

            "port": "8080",

            "name": "http-proxy"

        }]

    }]

}
```

 

# 服务提供组件/应用组件

> 从`资产服务组件`结果中，过滤出`http`服务扫出 `服务提供组件/应用组件`

```python
{
	"whatweb": [{
		"192.168.1.2": {
			"http": {
				"port": 8000
			},
			"Werkzeug": {
				"version": "0.14.1"
			}
		}
	}, {
		"www.discuz.net": {
			"nginx": {},
			"http": {
				"port": 80
			},
			"web": {
				"pl_version": "5.3.29",
				"pl": "PHP"
			}
		}
	}, {
		"www.miui.com": {
			"http": {
				"port": 80
			},
			"Server": {
				"version": "1.12.2"
			}
		}
	}, {
		"www.seebug.org": {
			"nginx": {},
			"http": {
				"port": 80
			}
		}
	}, {
		"www.discuz.net": {				   #资产(ip/域名)
			"Discuz!": {					#组件名：
                							  #组件属性：
				"home_page": "/forum.php",	    #家目录
				"deploy_path": "/",			    #部署路径
				"version": "X3.3",				#组件版本
				"pl_version": "5.3.29",			#编程语言版本
				"pl": "PHP"						#编程语言
			},
			"nginx": {},				   #提供服务(service_provider)
			"http": {					   #服务(service)
				"port": 80
			}
		}
	}, {
		"www.czqsy.net": {
			"web": {					   #发现不了组件时,默认用web代替
				"pl": "ASP.NET"
			},
			"Microsoft-IIS": {
				"version": "6.0"
			},
			"http": {
				"port": 80
			}
		}
	}]
}
```