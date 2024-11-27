#!/usr/bin/python3
# -*- coding:utf-8 -*-


import json
import os
import tqdm
import argparse



def generate_cve(args):
    for _parent, _dirs, _files in os.walk(args.cve_path):
        for _dir in tqdm.tqdm(_dirs):
            print("currently processing %s" % _dir)
            current_path = os.path.join(_parent, _dir)

            # 提取json格式的cve的description部分
            for parent, dirs, files in os.walk(current_path):
                for file in tqdm.tqdm(files):
                    json_file = os.path.join(current_path, file)
                    with open((json_file),'r',encoding='utf8') as fp:
                        # this_dict = dict()
                        json_data = json.load(fp)
                        cve = json_data["containers"]["cna"]
                        if "descriptions" in cve:
                            text = json_data["containers"]["cna"]["descriptions"][0]["value"]
                            filename = file.split('.')[0]
                            text = filename + ": " + text
                            this_dict = text.strip()
                        else:
                            continue

                    # 统一将一个文件夹下提取完成的cve生成为一个txt文件
                    with open(os.path.join(args.generate_dir, _dir + "-" + "CVE-total.txt"), 'a') as f:
                        f.write(json.dumps(this_dict, ensure_ascii=False))
                        f.write("\n")
                    # for feature_data in feature_datas:
                    #     f.write(feature_data + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test for argparse')

    # 原始cve文件目录地址
    parser.add_argument("--cve_path", type=str,
                        help='''Path of the pcap dataset path(e.g., "/Users/cglin/Desktop/DCS/application/sliced/")''')

    # 提取后的txt文件目录地址
    parser.add_argument("--generate_dir", type=str,
                        help='''Path of the corpora dataset path(e.g., "/Users/cglin/Desktop/DCS/application/corpora/")''')


    args = parser.parse_args()

    # generate txt for cve
    generate_cve(args)
