# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
from xml.dom import minidom
import urllib2

class Vuln(ABVuln):
    vuln_id = 'Flash_0000' # 平台漏洞编号
    name = 'Flash crossdomain.xml CSRF' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XXE # 漏洞类型
    disclosure_date = '2013-10-28'  # 漏洞公布时间
    desc = '''
        Flash crossdomain.xml跨站请求伪造漏洞。
    ''' # 漏洞描述
    ref = 'Unknown' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Flash'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '77029922-3abc-4765-8e72-594ed6a78e25' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/crossdomain.xml'
            html = urllib2.urlopen(urllib2.Request(vul_url)).read()
            if not '<cross-domain-polic' in html:
                return 
            else:
                xmldom = minidom.parseString(html)
                for o in xmldom.getElementsByTagName('allow-access-from'):
                    domain = o.getAttribute('domain').strip()
                    if domain == '*':
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:s
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()