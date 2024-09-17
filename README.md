# Distributed-Pcap-Dataset-Processing

## 指令格式

``````
/Library/Frameworks/Python.framework/Versions/3.10/bin/python3 /Users/cglin/Desktop/Distributed-Pcap-Dataset-Processing/pretrain/corpora_generation.py --pcap_path /Users/cglin/Desktop/pcap_data --corpora_dir /Users/cglin/Desktop --corpora_name a.txt
``````

## 输入文件格式

- pcap_data
  - A
    - facebook_audio1a.pcap
    - facebook_audio1b.pcap
    - facebook_audio2a.pcap

## 输出文件格式

- txt文件
- 一行一条数据（记得\n）

## demo

- 百度网盘链接
  - 链接: https://pan.baidu.com/s/1QXB6bnfE_G2STFeVG8tFkg 
  - 提取码: 1101


 # pretrain/corpora_generation_multiprocessing.py

## 指令格式

``````
python /data/dell/Distributed-Pcap-Dataset-Processing/pretrain/corpora_generation_multiprocessing.py --pcap_path /data/dell/processed_data/dataset_name/pcapng2pcap --corpora_dir /data/dell/processed_data/dataset_name/corpora
``````

## 输入文件格式

- pcap_data
  - A
    - facebook_audio1a.pcap
    - facebook_audio1b.pcap
    - facebook_audio2a.pcap

## 输出文件格式

- txt文件
- 三行为一个packet：一行header，一行payload，一行空格

# pretrain/split_header_payload.py

## 指令格式
``````
python /data/dell/Distributed-Pcap-Dataset-Processing/pretrain/split_header_payload.py --corpora_dir /data/dell/processed_data/dataset_name/corpora --dataset_dir /data/dell/processed_data/dataset_name --dataset_name application_raw
``````


## 输入文件格式

- dataset_name
  - corpora
    - facebook_audio1a.txt
    - facebook_audio1b.txt
    - facebook_audio2a.txt
   
## 输出文件格式

- 三个txt文件，header，payload，packet
- 一行一条数据
