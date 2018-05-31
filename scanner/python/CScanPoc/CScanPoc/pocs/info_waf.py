# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'info_waf' # 平台漏洞编号，留空
    name = 'WAF检测' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2018-5-17'  # 漏洞公布时间
    desc = '''
        检测目前市面上常见的Web Waf，依靠返回包里的HTTP状态码的特征来判断Waf是否存在。
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'waf'  # 漏洞应用名称
    product_version = '1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '73a9c433-6a1f-4ee0-a944-78c790293e25'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            wafs = {
                "360 Web Application Firewall (360)":["X-Powered-By-360wzb",r"wangzhan\.360\.cn"],
                "Airlock (Phion/Ergon)":["",r"\AAL[_-]?(SESS|LB)="],
                "Anquanbao Web Application Firewall (Anquanbao)":["X-Powered-By-Anquanbao",r"MISS"],
                "Yunjiasu Web Application Firewall (Baidu)":["X-Server",r"fhl"],
                "Barracuda Web Application Firewall (Barracuda Networks)":["",r"barra"],
                "BIG-IP Application Security Manager (F5 Networks)":["",r"BigIP|BIGipServer"],
                "BinarySEC Web Application Firewall (BinarySEC)":["binarysec",r"BinarySec"],
                "BlockDoS":["",r"BlockDos\.net"],
                "Cisco ACE XML Gateway (Cisco Systems)":["",r"ACE XML Gateway"],
                "CloudFlare Web Application Firewall (CloudFlare)":["",r"cloudflare-nginx"],
                "IBM WebSphere DataPower (IBM)":["X-Backside-Transport",r"\A(OK|FAIL)"],
                "dotDefender (Applicure Technologies)":["X-dotDefender-denied",r"1"],
                "EdgeCast WAF (Verizon)":["",r"\AECDF"],
                "FortiWeb Web Application Firewall (Fortinet Inc.)":["",r"\AFORTIWAFSID="],
                "Hyperguard Web Application Firewall (art of defence Inc.)":["",r"\AODSESSION="],
                "Incapsula Web Application Firewall (Incapsula/Imperva)":["X-CDN",r"Incapsula"],
                "Jiasule Web Application Firewall (Jiasule)":["",r"jiasule-WAF"],
                "ModSecurity: Open Source Web Application Firewall (Trustwave)":["",r"Mod_Security|NOYB"],
                "NetContinuum Web Application Firewall (NetContinuum/Barracuda Networks)":["",r"\ANCI__SessionId="],
                "NetScaler (Citrix Systems)":["",r"\ANS-CACHE"],
                "Profense Web Application Firewall (Armorlogic)":["",r"Profense"],
                "AppWall (Radware)":["",r"X-SL-CompState"],
                "Safedog Web Application Firewall (Safedog)":["X-Powered-By",r"WAF/2.0"],
                "Sucuri WebSite Firewall":["",r"Sucuri/Cloudproxy"],
                "Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)":["",r"\Ast8(id|_wat|_wlf)"],
                "TrafficShield (F5 Networks)":["",r"F5-TrafficShield"],
                "UrlScan (Microsoft)":["",r"Rejected-By-UrlScan"],
                "USP Secure Entry Server (United Security Providers)":["",r"Secure Entry Server"],
                "Varnish FireWall (OWASP)":["",r"X-Varnish"],
                "WebKnight Application Firewall (AQTRONIX)":["",r"WebKnight"],
            }
            code, head, body, error, _ = hh.http(arg)
                       
            for waf in wafs:
                if wafs[waf][0] in head and re.search(wafs[waf][1],head,re.IGNORECASE):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            arg = '{target}'.format(target=self.target)
            wafs = {
                "360 Web Application Firewall (360)":["X-Powered-By-360wzb",r"wangzhan\.360\.cn"],
                "Airlock (Phion/Ergon)":["",r"\AAL[_-]?(SESS|LB)="],
                "Anquanbao Web Application Firewall (Anquanbao)":["X-Powered-By-Anquanbao",r"MISS"],
                "Yunjiasu Web Application Firewall (Baidu)":["X-Server",r"fhl"],
                "Barracuda Web Application Firewall (Barracuda Networks)":["",r"barra"],
                "BIG-IP Application Security Manager (F5 Networks)":["",r"BigIP|BIGipServer"],
                "BinarySEC Web Application Firewall (BinarySEC)":["binarysec",r"BinarySec"],
                "BlockDoS":["",r"BlockDos\.net"],
                "Cisco ACE XML Gateway (Cisco Systems)":["",r"ACE XML Gateway"],
                "CloudFlare Web Application Firewall (CloudFlare)":["",r"cloudflare-nginx"],
                "IBM WebSphere DataPower (IBM)":["X-Backside-Transport",r"\A(OK|FAIL)"],
                "dotDefender (Applicure Technologies)":["X-dotDefender-denied",r"1"],
                "EdgeCast WAF (Verizon)":["",r"\AECDF"],
                "FortiWeb Web Application Firewall (Fortinet Inc.)":["",r"\AFORTIWAFSID="],
                "Hyperguard Web Application Firewall (art of defence Inc.)":["",r"\AODSESSION="],
                "Incapsula Web Application Firewall (Incapsula/Imperva)":["X-CDN",r"Incapsula"],
                "Jiasule Web Application Firewall (Jiasule)":["",r"jiasule-WAF"],
                "ModSecurity: Open Source Web Application Firewall (Trustwave)":["",r"Mod_Security|NOYB"],
                "NetContinuum Web Application Firewall (NetContinuum/Barracuda Networks)":["",r"\ANCI__SessionId="],
                "NetScaler (Citrix Systems)":["",r"\ANS-CACHE"],
                "Profense Web Application Firewall (Armorlogic)":["",r"Profense"],
                "AppWall (Radware)":["",r"X-SL-CompState"],
                "Safedog Web Application Firewall (Safedog)":["X-Powered-By",r"WAF/2.0"],
                "Sucuri WebSite Firewall":["",r"Sucuri/Cloudproxy"],
                "Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)":["",r"\Ast8(id|_wat|_wlf)"],
                "TrafficShield (F5 Networks)":["",r"F5-TrafficShield"],
                "UrlScan (Microsoft)":["",r"Rejected-By-UrlScan"],
                "USP Secure Entry Server (United Security Providers)":["",r"Secure Entry Server"],
                "Varnish FireWall (OWASP)":["",r"X-Varnish"],
                "WebKnight Application Firewall (AQTRONIX)":["",r"WebKnight"],
            }
            code, head, body, error, _ = hh.http(arg)
                       
            for waf in wafs:
                if wafs[waf][0] in head and re.search(wafs[waf][1],head,re.IGNORECASE):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，检测到目标的Waf为{waf}'.format(
                    target=self.target,name=self.vuln.name,waf=waf))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()