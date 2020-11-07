#! /usr/bin/env python
#__version__ = 1.1
'''
how to run pcap2df_normal_data.py
    $python2 pcap2df_normal_data.py --pcap /home/noob/Downloads/extract/extract1/104asdu.pcap --protocol  104asdu --utc
'''
from dateutil import parser
from datetime import datetime
from StringIO import StringIO
import csv
import argparse
import time
import os
import sys

# lambdas


def dat(): return time.strftime("%Y-%m-%d %H:%M:%S")
def date2epoch(x): return int(time.mktime(parser.parse(x).timetuple()))
def getUtc(x): return datetime.utcfromtimestamp(x)


protocolFields = {
    "tcp": ['frame', 'protocol', 'source_ip', 'source_port', 'dest_ip',
            'dest_port', 'frame_length', 'tcp_flag', 'data', 'date', 'time'],

    "udp": ['frame', 'protocol', 'source_ip', 'source_port', 'dest_ip',
            'dest_port', 'frame_length', 'info', 'data', 'date', 'time'],
    # zbee_nwk - https://www.wireshark.org/docs/dfref/z/zbee_nwk.html
    # https://www.wireshark.org/docs/dfref/f/frame.html

    "104asdu": ['frame', 'frame_len', 'time', 'src_ip', 'src_port',\
                'dst_ip', 'dst_port', 'win_size', 'tcp_len', 'flags',\
                'ttl', 'ip_len', 'tot_len', 'ip_id', 'start', 'apdu_len',\
                'type', 'rx', 'tx', 'type_id', 'causeTx', 'ioa', 'addr_asdu', 'oa', 'sq'],

    "icmp": ['frame', 'protocol', 'source_ip', 'dest_ip', 'icmp_type',\
             'icmp_code', 'icmp_seq', 'frame_length', 'data', 'date', 'time', 'icmp_ident_be', 'icmp_ident_le'],

    "ipv6": ['frame', 'protocol', 'source_ip', 'dest_ip', 'frame_length', 'source_port', 'dest_port', 'ipv6_source_ip', 'ipvs_dst_ip', 'data', 'date', 'time']
}

tsharkCmds = {
    "tcp": 'tshark -tud -n -r %s -E separator=/t -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.len -e tcp.flags -e data tcp and not "(ipv6 or icmp)" > %s',

    "udp": 'tshark -tud -n -r %s -E separator=/t -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e udp.srcport -e ip.dst -e udp.dstport -e frame.len -e _ws.col.Info -e data udp and not "(ipv6 or icmp)" > %s',

    "104asdu": 'tshark -tud -n -r %s -E separator=/t -T fields -e frame.number -e frame.len -e ip.proto -e frame.time -e\
        ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.window_size_value -e tcp.hdr_len -e tcp.flags -e \
        ip.ttl -e ip.hdr_len -e ip.len -e ip.id -e 104asdu.start -e 104apci.apdulen -e 104apci.type -e \
        104apci.rx -e 104apci.tx -e 104asdu.typeid -e 104asdu.causetx -e 104asdu.ioa -e 104asdu.addr -e \
        104asdu.oa -e 104asdu.bcr.sq -e\
        data 104apci and not "(ipv6 or icmp)"> %s',

    "icmp": 'tshark -tud -n -r %s -E separator=/t -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e ip.dst -e icmp.type -e icmp.code -e icmp.ident -e icmp.seq -e frame.len -e data icmp and not "(ipv6 or tcp or udp)" > %s',

    "ipv6": 'tshark -tud -n -r %s -E separator=/t -T fields -e frame.number -e ip.proto -e frame.time -e \
        ip.src -e ip.dst -e frame.len -e udp.srcport -e udp.dstport -e ipv6.src -e ipv6.dst -e data ipv6 > %s'
}

# The info column name seems to change depending on tshark version.
# _ws.col.Info
# col.Info


def ExtractPcapData(pcap, protocol):
    print dat(), "Processing:", pcap

    outputFileName = "%s_%s.txt" % (pcap.split(".")[0], protocol.upper())
    tsharkBaseCmd = tsharkCmds.get(protocol)
    execTsharkCmd = tsharkBaseCmd % (pcap, outputFileName)

    b = os.popen(execTsharkCmd).read()

    return outputFileName


def CreateCsv(outputFileName, protocol, convertTime):
    csvEntry = {}

    data = open(outputFileName, "r").read().strip().split("\n")
    csvFileName = outputFileName.replace(".txt", ".csv")
    csvFields = protocolFields.get(protocol)

    # print dat(),"Creating:",csvFileName

    with open(csvFileName, "w") as csvfile:
        # modeline for automation
        writer = csv.DictWriter(csvfile, fieldnames=csvFields)
        writer.writeheader()

        for entry in data:
            entry = entry.split('\t')

            try:
                timestamp = parser.parse(entry[2].split(
                    '.')[0]).strftime("%Y-%m-%d %H:%M:%S")
            except:
                print "There is a problem processing PCAP. If the error occured while processing UDP packets, try upgrading tshark."
                sys.exit()

            if convertTime:
                # Convert timestamp to UTC to match alerts
                timestamp = str(getUtc(date2epoch(timestamp)))
            else:  # Test this code,
                pass

            eventDate, eventTime = timestamp.split()
            del entry[2]
            entry.append(eventDate)
            entry.append(eventTime)

            if (protocol == "udp") and (len(csvFields) != len(entry)):
                # No data found in packet
                entry.insert(8, '')
            else:
                pass

            if (protocol == "104asdu") and (len(csvFields) != len(entry)):
                # No data found in packet
                entry.insert(8, '')
            else:
                pass

            if protocol == "icmp":
                try:
                    identBE, identLE = entry[-6].split(',')
                except:
                    identBE, identLE = ("NA", "NA")

                del entry[-6]  # ICMP
                entry.append(identBE)  # ICMP
                entry.append(identLE)  # ICMP

                if len(csvFields) != len(entry):
                    # No data found in packet. This will probably never happen, but just in case.
                    entry.insert(8, '')
                else:
                    pass

            csvEntry = dict(zip(csvFields, entry))  # mode line for automation
            writer.writerow(csvEntry)

    return csvFileName


def main():
    aParser = argparse.ArgumentParser()
    aParser.add_argument("--pcap", help="input file", required=True)
    aParser.add_argument(
        "--protocol", help="104asdu: IEC 60870-5-104-Asdu Protocol", required=True)
    aParser.add_argument(
        "--utc", help="convert timestamps to UTC", required=False, action="store_true")

    args = aParser.parse_args()
    pcap = args.pcap
    protocol = args.protocol
    convertTime = args.utc

    outputFileName = ExtractPcapData(pcap, protocol)
    csvFileName = CreateCsv(outputFileName, protocol, convertTime)


if __name__ == '__main__':
    main()

# END
