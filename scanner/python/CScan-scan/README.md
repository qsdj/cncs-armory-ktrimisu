# 使用

 

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

> 没有显示`PL` 或`product` 或`HTTPServer`, 没有扫出

```python
{
	"whatweb": [{					# 服务提供组件/应用组件
		"http://192.168.1.2:8000": {		# 目标ip+端口(http)
			"HTTPServer": {			# http 服务器
				"version": "0.14.1",
				"name": "Werkzeug"
			}
		}
	}, {
		"http://www.discuz.net:80": {
			"HTTPServer": {
				"name": "nginx"
			},
			"PL": {				# 编程语言
				"version": "5.3.29",
				"name": "PHP"
			}
		}
	}, {
		"http://www.miui.com:80": {
			"HTTPServer": {
				"version": "1.12.2",
				"name": "Server"
			}
		}
	}, {
		"http://www.seebug.org:80": {
			"HTTPServer": {
				"name": "nginx"
			}
		}
	}, {
		"http://www.discuz.net/forum.php": {
			"product": {			# 组件:
				"deploy_path": "/",	# 程序安装目录（目前扫目录功能还没有做，默认为 "/" ）
				"version": "X3.3",	# 版本
				"name": "Discuz!"	# 组件名称
			},
			"HTTPServer": {
				"name": "nginx"
			},
			"PL": {
				"version": "5.3.29",
				"name": "PHP"
			}
		}
	}, {
		"http://www.czqsy.net:80": {
			"HTTPServer": {
				"version": "6.0",
				"name": "Microsoft-IIS"
			},
			"PL": {
				"name": "ASP.NET"
			}
		}
	}]
}
```
