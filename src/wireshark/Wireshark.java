package wireshark;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.JPacket;
import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;
import java.util.ArrayList;
import org.jnetpcap.packet.format.FormatUtils;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.tcpip.Http;

public class Wireshark {

	public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	/*	public static Rip rip = new Rip() {
			void printheader() {
			System.out.println(rip.getHeader());
			}
			}; */
	
	public static Arp arp = new Arp();
	public static Payload payload = new Payload();
	public static byte[] payloadContent;
	public static boolean readdata = false;	public static byte[] myinet = new byte[3];
	public static byte[] mymac = new byte[5];

	public static InetAddress inet;
	public static Enumeration e;
	public static NetworkInterface n;
	public static Enumeration ee;

  public static void main(String args[]) throws Exception {
    // chapter 2.2-4
    // initiate packet capture device
    final int snaplen = 64*1024;
    final int flags = Pcap.MODE_PROMISCUOUS;
    final int timeout = 10*1000;
    final StringBuilder errbuf = new StringBuilder();
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}
		System.out.println("Network devices found:");
		int i = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
					description);
		}
                Scanner sc=new Scanner (System.in);
                int s=sc.nextInt();
		PcapIf device = alldevs.get(s); // Get first device in list
		System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription()
						: device.getName());
		
//    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
//    if (pcap == null) {
//      System.out.println("Error while opening device for capture: " + errbuf.toString());  
//      return;
//    }
//////
////		
////		
////	
////
/////////////////////////////////////////////////////////////////////////new start capture
//	 PcapPacketHandler<String> pcappackethandler;
//            pcappackethandler = new PcapPacketHandler<String>() {
//                public void nextPacket(PcapPacket packet, String user) {
//                    byte[] data = packet.getByteArray(0, packet.size()); // the package data
//                    byte[] sIP = new byte[4];
//                    byte[] dIP = new byte[4];
//                    //  Ip4 ip = new Ip4();
//                    
//                    if (packet.hasHeader(ip)) {
//                        sIP=ip.source();
//                        dIP=ip.destination();
//                        /* Use jNetPcap format utilities */
//                        String sourceIP =
//                                org.jnetpcap.packet.format.FormatUtils.ip(sIP);
//                        String destinationIP =
//                                org.jnetpcap.packet.format.FormatUtils.ip(dIP);
//                        //////////////////////////////////////////////////////////typppppppppppppppppppppppppppp
//                        String type = Integer.toHexString(ip.type());
//
//                        
//                        System.out.println("srcIP=" + sourceIP +
//                                " dstIP=" + destinationIP +
//                                " caplen=" + packet.getCaptureHeader().caplen()+ "type= "+type);
//                       System.out.println("IP checksum:\t"+ip.checksum());
//                        
//                         System.out.println("IP header:\t"+ip.toString());
//                    }
//                    if (packet.hasHeader(eth)
//                            ) {
//                     
//
//                        System.out.println("Ethernet type:\t" + eth.typeEnum());
//                        System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
//                        System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));
//                        String hexdump = packet.toHexdump(packet.size(), false, false, true);
//                        
//                        
//                       
//                        data = FormatUtils.toByteArray(hexdump);
//                        
//                        JMemory packet2 = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
//                      
//                        
//                    }
//                    if (packet.hasHeader(tcp)
//                            ) {
//                        System.out.println("TCP src port:\t" + tcp.source());
//                        System.out.println("TCP dst port:\t" + tcp.destination());
//                        System.out.println("Tcp acknowledge:\t"+tcp.ack());
//                        
//                         System.out.println("Tcp header:\t"+tcp.toString());
//                        
//                        
//                    } else if (packet.hasHeader(udp)
//                            ) {
//                        System.out.println("UDP src port:\t" + udp.source());
//                        System.out.println("UDP dst port:\t" + udp.destination());
//                        System.out.println("UDP Checksum:\t"+udp.checksum());
//                        
//                         System.out.println("UDP header:\t"+udp.toString());
//                    }
//                    /*			if (pcappacket.hasHeader(rip) &&
//                    readdata == true) {
//                    System.out.println("RIP count:\t" + rip.count());
//                    System.out.println("RIP header:\t" + rip.getHeader());
//                    } */
//                    if (packet.hasHeader(arp)
//                            ) {
//                        
//                        
//                        System.out.println("ARP Packet!");
//                       
//                        
//                         System.out.println("ARP header:\t"+arp.toString());
//                        readdata = true;
//                    }
//                    if (packet.hasHeader(payload)
//                            ) {
//                        payloadContent = payload.getPayload();
//                        System.out.println("Payload:\n");
//                        System.out.println("Payload header:\t"+payload.toString());
//                    }
//                    if (readdata == true) System.out.println("-\t-\t-\t-\t-");
//                    readdata = false;
//                }
//            };
//         pcap.loop(-1, pcappackethandler, "pressure");
//         
//		pcap.close();
////////////////////////////////////////////////////////////////////////////////////////// finish

//////////////////////////////////READ FROMFILEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE///////////////// 
///////////////////////////////////////////////////////////////////////////////////////////////
final String FILENAME = "tmp-capture-file.cap";  
      //  final StringBuilder errbuf = new StringBuilder();  
  
       Pcap  pcap = Pcap.openOffline(FILENAME, errbuf);  
        if (pcap == null) {  
            System.err.println(errbuf); // Error is stored in errbuf if any  
            return;  
        }  
  
//        
       pcap.loop(10, new JPacketHandler<StringBuilder>() {  
//  
//             
//            final Tcp tcp = new Tcp();  
//  
//           
//            final Http http = new Http();  
//  
//          
             public void nextPacket(JPacket packet, StringBuilder errbuf) {  
//  



 byte[] data = packet.getByteArray(0, packet.size()); // the package data
                    byte[] sIP = new byte[4];
                    byte[] dIP = new byte[4];
                    //  Ip4 ip = new Ip4();
                    
                    if (packet.hasHeader(ip)) {
                        sIP=ip.source();
                        dIP=ip.destination();
                        /* Use jNetPcap format utilities */
                        String sourceIP =
                                org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                        String destinationIP =
                                org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                        //////////////////////////////////////////////////////////typppppppppppppppppppppppppppp
                        String type = Integer.toHexString(ip.type());

                        
                        System.out.println("srcIP=" + sourceIP +
                                " dstIP=" + destinationIP +
                                " caplen=" + packet.getCaptureHeader().caplen()+ "type= "+type);
                       System.out.println("IP checksum:\t"+ip.checksum());
                        
                         System.out.println("IP header:\t"+ip.toString());
                    }
                    if (packet.hasHeader(eth)
                            ) {
                     

                        System.out.println("Ethernet type:\t" + eth.typeEnum());
                        System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
                        System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));
                        String hexdump = packet.toHexdump(packet.size(), false, false, true);
                        
                        
                       
                        data = FormatUtils.toByteArray(hexdump);
                        
                        JMemory packet2 = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
                      
                        
                    }
                    if (packet.hasHeader(tcp)
                            ) {
                        System.out.println("TCP src port:\t" + tcp.source());
                        System.out.println("TCP dst port:\t" + tcp.destination());
                        System.out.println("Tcp acknowledge:\t"+tcp.ack());
                        
                         System.out.println("Tcp header:\t"+tcp.toString());
                        
                        
                    } else if (packet.hasHeader(udp)
                            ) {
                        System.out.println("UDP src port:\t" + udp.source());
                        System.out.println("UDP dst port:\t" + udp.destination());
                        System.out.println("UDP Checksum:\t"+udp.checksum());
                        
                         System.out.println("UDP header:\t"+udp.toString());
                    }
                    /*			if (pcappacket.hasHeader(rip) &&
                    readdata == true) {
                    System.out.println("RIP count:\t" + rip.count());
                    System.out.println("RIP header:\t" + rip.getHeader());
                    } */
                    if (packet.hasHeader(arp)
                            ) {
                        
                        
                        System.out.println("ARP Packet!");
                       
                        
                         System.out.println("ARP header:\t"+arp.toString());
                        readdata = true;
                    }
                    if (packet.hasHeader(payload)
                            ) {
                        payloadContent = payload.getPayload();
                        System.out.println("Payload:\n");
                        System.out.println("Payload header:\t"+payload.toString());
                    }
                    if (readdata == true) System.out.println("-\t-\t-\t-\t-");
                    readdata = false;

















//                /* 
//                 * Here we receive 1 packet at a time from the capture file. We are 
//                 * going to check if we have a tcp packet and do something with tcp 
//                 * header. We are actually going to do this twice to show 2 different 
//                 * ways how we can check if a particular header exists in the packet and 
//                 * then get that header (peer header definition instance with memory in 
//                 * the packet) in 2 separate steps. 
//                 */  
//                if (packet.hasHeader(Tcp.ID)) {  
//  
//                    /* 
//                     * Now get our tcp header definition (accessor) peered with actual 
//                     * memory that holds the tcp header within the packet. 
//                     */  
//                    packet.getHeader(tcp);  
//  
//                    System.out.printf("tcp.dst_port=%d%n", tcp.destination());  
//                    System.out.printf("tcp.src_port=%d%n", tcp.source());  
//                    System.out.printf("tcp.ack=%x%n", tcp.ack());  
//  
//                }  
//  
//                /* 
//                 * An easier way of checking if header exists and peering with memory 
//                 * can be done using a conveniece method JPacket.hasHeader(? extends 
//                 * JHeader). This method performs both operations at once returning a 
//                 * boolean true or false. True means that header exists in the packet 
//                 * and our tcp header difinition object is peered or false if the header 
//                 * doesn't exist and no peering was performed. 
//                 */  
//                if (packet.hasHeader(tcp)) {  
//                    System.out.printf("tcp header::%s%n", tcp.toString());  
//                }  
//  
//                /* 
//                 * A typical and common approach to getting headers from a packet is to 
//                 * chain them as a condition for the if statement. If we need to work 
//                 * with both tcp and http headers, for example, we place both of them on 
//                 * the command line. 
//                 */  
//                if (packet.hasHeader(tcp) && packet.hasHeader(http)) {  
//                    /* 
//                     * Now we are guarranteed to have both tcp and http header peered. If 
//                     * the packet only contained tcp segment even though tcp may have http 
//                     * port number, it still won't show up here since headers appear right 
//                     * at the beginning of http session. 
//                     */  
//  
//                    System.out.printf("http header::%s%n", http);  
//  
//                    /* 
//                     * jNetPcap keeps track of frame numbers for us. The number is simply 
//                     * incremented with every packet scanned. 
//                     */  
//  
//                }  
//  
//                System.out.printf("frame #%d%n", packet.getFrameNumber());  
           }  
//  
       }, errbuf);
//  






 
  ///////////////////////////////////////////save in file////////////////////////////////////////////////
  
  
//String ofile = "tmp.cap";  
//PcapDumper dumper = pcap.dumpOpen(ofile); // output file  
//  
//JBufferHandler<PcapDumper> dumpHandler = new JBufferHandler<PcapDumper>() {  
//  
//  public void nextPacket(PcapHeader header, JBuffer buffer, PcapDumper dumper) {  
//  
//    dumper.dump(header, buffer);  
//  }  
//};  
//  
//pcap.loop(-1, dumpHandler, dumper);  
//                  
//File file = new File(ofile);  
//System.out.printf("%s file has %d bytes in it!\n", ofile, file.length());  
//                  
//dumper.close(); // Won't be able to delete without explicit close  
//    pcap.close();  




  }
}

