# coding: utf-8
import re
import urllib2
from distutils.version import LooseVersion

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Misfortune_0101' # 平台漏洞编号，留空
    name = 'Misfortune Cookie(CVE-2014-9222)' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-12-22'  # 漏洞公布时间
    desc = '''
    Misfortune Cookie(CVE-2014-9222)
    攻击者能够利用Misfortune Cookie漏洞, 将带有攻击负载的cookie发送到服务端, 获取管理员控制权限。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Misfortune'  # 漏洞应用名称
    product_version = '<=4.34'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '88da382a-0f3a-430b-bfc4-8b66bab14a35' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = '%s/Allegro' % self.target
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            ver = re.findall('RomPager Advanced Version (\\d+\\.\\d+)<br>', content)
            if ver and '<title>Allegro Copyright</title>' in content:
                if LooseVersion(ver[0]) < LooseVersion('4.34'):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()