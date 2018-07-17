# 使用

```shell
python main.py -h

python main.py -u <ip> -p <port(端口, 默认如下)> -r <rate(masscan的并发率, 默认1000)>

默认端口：
    21, 22, 23, 25, 53 ,69, 80, 110, 443, 1080, 1158, 1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001, 8000, 8080, 8081, 9080, 9090
```
## 输出之后结果都写在了 tmp 目录下

- Assets.json --- 资产结果
- SCA.json  --- 服务组件结果
- Whatweb.json  --- 服务提供组件/应用组件结果


# 结果说明
## 资产结果说明
```
tmp = {
	"assets": ["192.168.1.2", "192.168.1.1"]
}

tmp 字典中的 key为"assets"的  value 是list 存放扫出所有的资产ip。

```

## 服务组件结果
```
tmp = {
	"SCA": [{
		"192.168.1.2": [{
			"port": "3306",
			"name": "mysql"
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

tmp 字典中的 key为"SCA"的 value 是list；其中的每个元素都是字典，其key是ip，value 是list,存放多个端口
```

# 服务提供组件/应用组件结果
> whatweb扫出的东西比较复杂(固定取值会出现漏取得)，我只能过滤掉不想要的字段，
```
tmp = {
	"whatweb": [{
		"http://192.168.1.1:80": {
			"Boa-WebServer": {
				"version": ["0.94.13"]
			},
			"HTTPServer": {
				"string": ["Boa/0.94.13"]
			},
			"Script": {
				"string": ["javascript>top.location.replace("]
			}
		}
	}, {
		"http://192.168.1.1:8080": {
			"HTTPServer": {
				"string": ["Jetty(6.1.x)"]
			},
			"Jetty": {
				"version": ["6.1.x"]
			},
			"PoweredBy": {
				"string": ["Jetty://"]
			}
		}
	}]
}

tmp 字典中的 key为"whatweb"的 value 是 list；其中的每个元素都是字典，其key是扫描的 ip加端口 ，value 为 字典, 其value存放中存放着 扫出提供组件/应用组件
```