import os
import time
import argparse

def process_txt_files(args):
    packet_file = os.path.join(args.dataset_dir,args.dataset_name + "-packet.txt")
    header_file = os.path.join(args.dataset_dir,args.dataset_name + "-header.txt")
    payload_file = os.path.join(args.dataset_dir,args.dataset_name + "-payload.txt")
    with open(header_file, 'a') as hf, open(payload_file, 'a') as pf, open(packet_file, 'a') as cf:
         for filename in os.listdir(args.corpora_dir):
             if filename.endswith('.txt'):
                 file_path = os.path.join(args.corpora_dir, filename)
                 with open(file_path, 'r') as f:
                         lines = f.readlines()
                         for i in range(0, len(lines), 3):
                             hf.write(lines[i].strip() + '\n')
                             cf.write(lines[i].strip() + lines[i+1].strip()+'\n')
                             if lines[i+1].strip():
                                 pf.write(lines[i+1].strip() + '\n')



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test for argparse')

    parser.add_argument("--corpora_dir", type=str,
                                    help='''Path of the corpora dataset path(e.g., "/Users/cglin/Desktop/DCS/application/corpora/")''')

    parser.add_argument("--dataset_dir", type=str,
                                    help='''Path of the output dataset path(e.g., "/Users/cglin/Desktop/DCS/application/")''')

    parser.add_argument("--dataset_name", type=str,
                                            help='''Name of the dataset(e.g., "application_raw")''')
    args = parser.parse_args()


    start_time = time.time()
    process_txt_files(args)
    end_time = time.time()
    print('total time is {}'.format(str(end_time - start_time)))
