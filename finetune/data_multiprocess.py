#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import sys
import copy
import tqdm
import time
import scapy.all as scapy
import argparse
from multiprocessing import Process, cpu_count, Pool

## 多进程数据清洗模块
def clean_process(pcap_file, target_file):
    print('process {} starts'.format(os.getpid()))
    # 这是ET-BERT使用的默认DCS
    clean_protocols_DCS1 = '"not arp and not dns and not stun and not dhcpv6 and not icmpv6 and not icmp and not dhcp and not llmnr and not nbns and not ntp and not igmp and frame.len > 80"'
    # 这是对于application(17)任务而言，frame.len > 80最优的DCS
    cmd = "tshark -F pcap -r %s -Y %s -w %s"
    command = cmd % (pcap_file, clean_protocols_DCS1, target_file)
    os.system(command)
    
## 数据清洗模块
def data_clean(Raw_path, cleaned_path):
    print("Begin to Data Cleaning !")
    p = Pool(128)
    for _parent,_dirs,_files in os.walk(Raw_path):
        for _dir in tqdm.tqdm(_dirs):
            print("currently processing %s" % _dir)
            current_path = os.path.join(_parent, _dir)
            target_path = os.path.join(cleaned_path, _dir)
            
            # 如果不存在该目录，则创建该目录
            if not os.path.exists(target_path):
                print("[data_clean] : Creating target dir %s" % target_path)
                os.makedirs(target_path)
            
            # 正式的 data clean 实现
            for parent,dirs,files in os.walk(current_path):
                for file in tqdm.tqdm(files):
                    pcap_file = os.path.join(current_path, file)
                    target_file = os.path.join(target_path, file)
                    p.apply_async(clean_process, (pcap_file, target_file))
    p.close()
    p.join()
    print("Finish Data Cleaning !")
    return 0

## pcapng 2 pcap 模块
def pcapng2pcap(Raw_path, pcapng2pcap_path):
    
    print("Begin to convert pcapng to pcap.")

    for _parent,_dirs,_files in os.walk(Raw_path):
        for _dir in _dirs:
            print("currently processing %s" % _dir)
            current_path = os.path.join(_parent, _dir)
            target_path = os.path.join(pcapng2pcap_path, _dir)
            
            # 如果不存在该目录，则创建该目录
            if not os.path.exists(target_path):
                print("[pcapng2pcap] : Creating target dir %s" % target_path)
                os.makedirs(target_path)
            
            # 正式的 pcapng 2 pcap实现
            for parent,dirs,files in os.walk(current_path):
                for file in files:
                    pcapng_file = os.path.join(current_path, file)
                    pcap_file = os.path.join(target_path, file)
                    pcap_file = pcap_file.replace('.pcapng','.pcap')
                    cmd = "tshark -r %s -w %s -F libpcap"
                    command = cmd%(pcapng_file, pcap_file)
                    os.system(command)

    print("Finish convert pcapng to pcap")

## split .pcap 模块
def split_pcap(Raw_path, sliced_path):
    
    print("Begin to split pcap as session flows.") 
    
    for _parent,_dirs,_files in os.walk(Raw_path):
        for _dir in _dirs:
            print("currently processing %s" % _dir)
            current_path = os.path.join(_parent, _dir)
            target_path = os.path.join(sliced_path, _dir)
            
            # 如果不存在该目录，则创建该目录
            if not os.path.exists(target_path):
                print("[sliced] : Creating target dir %s" % target_path)
                os.makedirs(target_path)

            # 正式的 split pcap
            for parent,dirs,files in os.walk(current_path):
                for file in files:
                    pcap_file = os.path.join(current_path, file)
                    # cmd = "mono /Volumes/LCG_2/Datasets/SplitCap.exe -r %s -s session -o " + target_path 
                    cmd = "mono /Users/cglin/Desktop/ICT/Mining-Traffic-Classification/GPT_results/SplitCap.exe -r %s -s session -o " + target_path
                    # cmd = "mono /Users/cglin/Desktop/DCS/SplitCap2.exe -r %s -s session -o " + target_path

                    # with open(pcap_file, 'rb') as file_handle:
                    #     command = cmd % pcap_file
                    #     os.system(command)
                    # file_handle.close()
                    command = cmd%pcap_file
                    os.system(command)


    print("Finish split pcap as session flows")


if __name__ == '__main__':
    
    # Raw_path = "/Volumes/LCG_2/Datasets/USTC-TFC2016/Software/Raw"
    pcapng2pcap_path = "/Volumes/LCG_2/Datasets/ISCX-VPN/application/pcapng2pcap"
    sliced_path = "/Volumes/LCG_2/Datasets/ISCX-VPN/application/sliced"
    # cleaned_path = "/Users/cglin/Desktop/DCS/USTCTFC/Attack/cleaned_1"
    
    # if not os.path.exists(pcapng2pcap_path):
    #     print("[pcapng2pcap_path] : Creating target dir %s" % pcapng2pcap_path)
    #     os.makedirs(pcapng2pcap_path)
    #     pcapng2pcap(Raw_path, pcapng2pcap_path)
    
    if not os.path.exists(sliced_path):
        print("[sliced_path] : Creating target dir %s" % sliced_path)
        os.makedirs(sliced_path)
        split_pcap(pcapng2pcap_path, sliced_path)
    
    
    # if not os.path.exists(cleaned_path):
    #     print("[cleaned_path] : Creating target dir %s" % cleaned_path)
    #     os.makedirs(cleaned_path)
    #     data_clean(sliced_path, cleaned_path)
    
