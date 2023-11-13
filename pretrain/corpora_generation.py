#!/usr/bin/python3
#-*- coding:utf-8 -*-

import scapy.all as scapy
import binascii
import json
import os
import csv
from sklearn.model_selection import StratifiedShuffleSplit
import numpy as np
from flowcontainer.extractor import extract
import tqdm
import random
import argparse
import time
from multiprocessing import Process, cpu_count, Pool


def cut(obj, sec):
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    try:
        remanent_count = len(result[0])%4
    except Exception as e:
        remanent_count = 0
        print(1)
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

# 对数据报进行bigram操作
def bigram_generation(packet_datagram, packet_len, flag=True, num_interval=2):
    result = ''
    generated_datagram = cut(packet_datagram,1)
    token_count = 0

    # 如果使用bigram, 那么num_interval = 1, 否则正常情况下num_interval = 2

    for sub_string_index in range(0,len(generated_datagram),num_interval):
        if sub_string_index != (len(generated_datagram) - 1):
            token_count += num_interval
            if token_count > packet_len:
                break
            else:
                merge_word_bigram = generated_datagram[sub_string_index] + generated_datagram[sub_string_index + 1]
        else:
            break
        result += merge_word_bigram
        result += ' '
    if flag == True:
        result = result.rstrip()
    
    return result

def get_feature_packet(label_pcap, payload_len=128):
        
    # 判断长度是否为0
    if os.path.getsize(label_pcap) == 0:
        print("Current File Size = 0 !")
        return -1
    
    feature_data = []

    with scapy.PcapReader(label_pcap) as pcap_reader:
        for i, packet in tqdm.tqdm(enumerate(pcap_reader)):

        # 改变头部字段的信息
            if 'Ethernet' in packet:
                packet['Ethernet'].src = "00:00:00:00:00:00"
                packet['Ethernet'].det = "00:00:00:00:00:00"
            if 'IP' in packet:
                packet['IP'].src = "0.0.0.0"
                packet['IP'].dst = "0.0.0.0"
            if 'TCP' in packet: 
                packet['TCP'].sport = 0
                packet['TCP'].dport = 0
            
            packet_data = packet
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()
            new_packet_string = packet_string[0:]
            # 如果使用bigram, 那么num_interval = 1, 否则正常情况下num_interval = 2
            packet_data_string = bigram_generation(new_packet_string, packet_len=payload_len, flag = True, num_interval = 2)
            feature_data.append(packet_data_string)

    if len(feature_data) == 0:
        return -1

    return feature_data

def process_func(current_path, _dir, file, args):
    print('process {} starts'.format(os.getpid()))
    pcap_file = os.path.join(current_path, file)
    feature_datas = get_feature_packet(pcap_file, payload_len = 128)
    # 为每个pcap文件生成对应的txt语料文件
    if feature_datas == -1:
        return 0
    # 为每个pcap文件生成单独对应的txt语料文件
    with open(os.path.join(args.corpora_dir, _dir + '-' + file+"-encryptd_vocab.txt"), 'a') as f:
            for feature_data in feature_datas:
                f.write(feature_data + '\n')
    print('process {} ends'.format(os.getpid()))
    return 0

def generate_corpora(args):
    #设置进程数量
    p = Pool(4)
    for _parent,_dirs,_files in os.walk(args.pcap_path):
        for _dir in tqdm.tqdm(_dirs):
            print("currently processing %s" % _dir)
            current_path = os.path.join(_parent, _dir)

            # 正式的 corpora generation实现
            for parent,dirs,files in os.walk(current_path):
                for file in tqdm.tqdm(files):
                    p.apply_async(process_func, (current_path, _dir, file, args))
    p.close()
    p.join()
                # 统一生成为一个txt语料文件
                # with open(os.path.join(args.corpora_dir, args.corpora_name), 'a') as f:
                #     for feature_data in feature_datas:
                #         f.write(feature_data + '\n')


if __name__ == '__main__':


    parser = argparse.ArgumentParser(description='Test for argparse')

    # 切分后pacp文件的目录
    parser.add_argument("--pcap_path", type=str,
                        help='''Path of the pcap dataset path(e.g., "/Users/cglin/Desktop/DCS/application/sliced/")''')

    # corpora文件的目录地址
    parser.add_argument("--corpora_dir", type=str,
                        help='''Path of the corpora dataset path(e.g., "/Users/cglin/Desktop/DCS/application/sliced/")''')

    # corpora文件的文件名称
    parser.add_argument("--corpora_name", type=str,
                        help='''filename of the corpora dataset path(e.g., "encryptd_vocab_all.txt")''')

    args = parser.parse_args()

    # generate corpora

    print('main process is {}'.format(os.getpid()))
    print('core number is {}'.format(cpu_count()))
    start_time = time.time()
    generate_corpora(args)
    end_time = time.time()
    print('total time is {}'.format(str(end_time - start_time)))