# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://doc.scrapy.org/en/latest/topics/item-pipeline.html

import json
from urllib.parse import urlparse

class AkscanPipeline(object):
    def __init__(self):
        self.file = open('urls.json', 'w')

    def process_item(self, item, spider):
        content = json.dumps(dict(item), ensure_ascii=False) + "\n"
        self.file.write(content)
        return item

    def changing_data_structure(self):
        self.file = open('urls.json', 'r')
        domain = ''
        url_result = {'getallurls':{}}
        urls = {domain:[]}
        url_lists = []

        for oneline in self.file:
            dict_oneline = eval(oneline.split('\n')[0])
            if not domain:
                domain = urlparse(dict_oneline['url']).netloc
                urls = {domain:[]}
            url_lists.append(dict_oneline['url'])
        urls[domain] = url_lists
        url_result['getallurls']= urls
        self.file.close()

        self.file = open('urls.json', 'w')
        content = str(json.dumps(url_result, separators=(',', ':')))
        self.file.write(content)
        self.file.close()


    def close_spider(self, spider):
        self.file.close()
        self.changing_data_structure()
