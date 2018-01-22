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
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;
import java.util.ArrayList;
import org.jnetpcap.packet.format.FormatUtils;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.tcpip.Http;
import static wireshark.Wireshark.arp;
import static wireshark.Wireshark.eth;
import static wireshark.Wireshark.ip;
import static wireshark.Wireshark.payload;
import static wireshark.Wireshark.payloadContent;
import static wireshark.Wireshark.readdata;
import static wireshark.Wireshark.tcp;
import static wireshark.Wireshark.udp;

public class NewJFrame extends javax.swing.JFrame {

    public static Ip4 ip = new Ip4();
    public static Ethernet eth = new Ethernet();
    public static Tcp tcp = new Tcp();
    public static Udp udp = new Udp();
    public static Arp arp = new Arp();
    public static Payload payload = new Payload();
    public static byte[] payloadContent;
    public static boolean readdata = false;
    public static byte[] myinet = new byte[3];
    public static byte[] mymac = new byte[5];

    public static InetAddress inet;
    public static Enumeration e;
    public static NetworkInterface n;
    public static Enumeration ee;
    DefaultTableModel model1;
    DefaultTableModel model2;
    static int s;
    public static PcapIf device;
    public static Pcap pcap;
    int j = 0;
    String type;
    int index = 0;

    LinkedList<Packet> l = new LinkedList<>();
    public static boolean flag = true;
    Object rowData2[] = new Object[4];

    final StringBuilder errbuf = new StringBuilder();
    public static List<PcapIf> alldevs = new ArrayList<PcapIf>();

    public NewJFrame() {
        initComponents();

        model1 = (DefaultTableModel) jTable2.getModel();
        model2 = (DefaultTableModel) jTable1.getModel();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jTextField1 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        jTextArea2 = new javax.swing.JTextArea();
        jButton3 = new javax.swing.JButton();
        jScrollPane4 = new javax.swing.JScrollPane();
        jTable2 = new javax.swing.JTable();
        jLabel5 = new javax.swing.JLabel();
        jTextField2 = new javax.swing.JTextField();
        jButton4 = new javax.swing.JButton();
        jButton5 = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jButton7 = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jTextField3 = new javax.swing.JTextField();
        jTextField4 = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jButton8 = new javax.swing.JButton();
        jButton9 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel2.setFont(new java.awt.Font("Tahoma", 1, 24)); // NOI18N
        jLabel2.setText("  Wireshark");

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Frame No", "Source", "Destination", "Protocol"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jTable1MouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(jTable1);

        jTextField1.setFont(new java.awt.Font("Tahoma", 0, 10)); // NOI18N
        jTextField1.setText("Apply a displayed Filter");

        jButton1.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jButton1.setText("Start Capture");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jButton2.setText("Stop Capture");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jLabel1.setText("Detailed Information About The Selected Packet");

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jLabel3.setText("Hexa Representation About the Selected Packet");

        jTextArea2.setColumns(20);
        jTextArea2.setRows(5);
        jScrollPane3.setViewportView(jTextArea2);

        jButton3.setText("Exit");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jTable2.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Device Number", "Name", "Description"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jScrollPane4.setViewportView(jTable2);

        jLabel5.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jLabel5.setText("Choose One Of The Devices Available");

        jTextField2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField2ActionPerformed(evt);
            }
        });

        jButton4.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jButton4.setText("Done");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        jButton5.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jButton5.setText("Find Devices Available");
        jButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton5ActionPerformed(evt);
            }
        });

        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane2.setViewportView(jTextArea1);

        jButton7.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jButton7.setText("Start Offline Capture");
        jButton7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton7ActionPerformed(evt);
            }
        });

        jLabel4.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jLabel4.setText("Enter The File Name To Start Offline Capture");

        jTextField4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField4ActionPerformed(evt);
            }
        });

        jLabel6.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        jLabel6.setText("Enter the file name to save");

        jButton8.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        jButton8.setText("Save");
        jButton8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton8ActionPerformed(evt);
            }
        });

        jButton9.setText("OK");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane4)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jButton5)
                                .addGap(18, 18, 18)
                                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 235, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(jButton4)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 100, Short.MAX_VALUE)))
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGap(30, 30, 30)
                                .addComponent(jLabel4)
                                .addGap(35, 35, 35)
                                .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 195, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGap(100, 100, 100)
                                .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(44, 44, 44))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGap(89, 89, 89)
                                .addComponent(jButton7, javax.swing.GroupLayout.PREFERRED_SIZE, 175, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jButton8)
                                .addGap(85, 85, 85))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 155, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(313, 313, 313)
                        .addComponent(jButton3)
                        .addGap(14, 14, 14))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 312, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGap(49, 49, 49)
                                .addComponent(jButton1)
                                .addGap(18, 18, 18)
                                .addComponent(jButton2)))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane2)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jScrollPane1)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 312, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 463, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(jButton9)))
                                .addGap(0, 0, Short.MAX_VALUE)))))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jButton3))
                    .addComponent(jLabel2))
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(21, 21, 21)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jButton5)
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(jLabel5)
                                .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jButton4))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel4)
                            .addComponent(jLabel6))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jButton7)
                            .addComponent(jButton8)))
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 92, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButton1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jButton2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton9))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 91, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 137, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 126, Short.MAX_VALUE)
                .addGap(23, 23, 23))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        l.clear();
        index = 0;
        flag = true;
        jTextArea1.setText("");

        final int snaplen = 64 * 1024;
        final int flags = Pcap.MODE_PROMISCUOUS;
        final int timeout = 10 * 1000;
        final StringBuilder errbuf = new StringBuilder();
        List<PcapIf> alldevs = new ArrayList<PcapIf>();

        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.out.println("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        Thread thread;
        thread = new Thread(new Runnable() {

            @Override
            public void run() {

                while (flag == true) {

                    PcapPacketHandler<String> pcappackethandler;
                    pcappackethandler = new PcapPacketHandler<String>() {
                        public void nextPacket(PcapPacket packet, String user) {

                            String data1 = "";
                            String payload1 = "";

                            if (flag == false) {
                                pcap.breakloop();
                            }
                            byte[] data = packet.getByteArray(0, packet.size());
                            byte[] sIP = new byte[4];
                            byte[] dIP = new byte[4];

                            if (packet.hasHeader(ip)) {
                                sIP = ip.source();
                                dIP = ip.destination();
                                /* Use jNetPcap format utilities */
                                String sourceIP
                                        = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                                String destinationIP
                                        = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                                String type = Integer.toHexString(ip.type());

                                index = j++;
                                rowData2[0] = index;
                                rowData2[1] = sourceIP;
                                rowData2[2] = destinationIP;
                                rowData2[3] = "IP";
                                model2.addRow(rowData2);

                                if (packet.hasHeader(payload)) {
                                    payloadContent = payload.getPayload();
                                    System.out.println("Payload:\n");
                                    System.out.println("Payload header:\t" + payload.toString());
                                    payload1 = "Payload header:\t" + payload.toString();

                                    //jTextArea2.append("Payload:\n" + "\n" + "Payload header:\t" + payload.toString() + "\n");
                                }

                                data1 = "srcIP=" + sourceIP + "\n" + " dstIP=" + destinationIP + "\n" + " caplen=" + packet.getCaptureHeader().caplen() + "\n" + "type= " + type + "\n" + "IP checksum:\t" + ip.checksum() + "\n" + "IP header:\t" + ip.toString() + "\n";
                                Packet p1 = new Packet(index, data1, payload1);
                                l.add(p1);

                                System.out.println("srcIP=" + sourceIP
                                        + " dstIP=" + destinationIP
                                        + " caplen=" + packet.getCaptureHeader().caplen() + "type= " + type);
                                System.out.println("IP checksum:\t" + ip.checksum());

                                System.out.println("IP header:\t" + ip.toString());

                            }
                            if (packet.hasHeader(eth)) {

                                System.out.println("Ethernet type:\t" + eth.typeEnum());
                                System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
                                System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));
                                String hexdump = packet.toHexdump(packet.size(), false, false, true);

                                index = j++;
                                rowData2[0] = index;
                                rowData2[1] = FormatUtils.mac(eth.source());
                                rowData2[2] = FormatUtils.mac(eth.destination());
                                rowData2[3] = "ETH";
                                model2.addRow(rowData2);

                                if (packet.hasHeader(payload)) {
                                    payloadContent = payload.getPayload();
                                    System.out.println("Payload:\n");
                                    System.out.println("Payload header:\t" + payload.toString());
                                    payload1 = "Payload header:\t" + payload.toString();

                                    //jTextArea2.append("Payload:\n" + "\n" + "Payload header:\t" + payload.toString() + "\n");
                                }
                                data1 = "Ethernet type:\t" + eth.typeEnum() + "\n" + "Ethernet src:\t" + FormatUtils.mac(eth.source()) + "\n" + "Ethernet dst:\t" + FormatUtils.mac(eth.destination());
                                Packet p1 = new Packet(index, data1, payload1);
                                l.add(p1);

                                data = FormatUtils.toByteArray(hexdump);

                                JMemory packet2 = new JMemoryPacket(JProtocol.ETHERNET_ID, data);

                            }
                            if (packet.hasHeader(tcp)) {

                                index = j++;
                                rowData2[0] = index;
                                rowData2[1] = tcp.source();
                                rowData2[2] = tcp.destination();
                                rowData2[3] = "TCP";
                                model2.addRow(rowData2);

                                System.out.println("TCP src port:\t" + tcp.source());
                                System.out.println("TCP dst port:\t" + tcp.destination());
                                System.out.println("Tcp acknowledge:\t" + tcp.ack());

                                System.out.println("Tcp header:\t" + tcp.toString());

                                if (packet.hasHeader(payload)) {
                                    payloadContent = payload.getPayload();
                                    System.out.println("Payload:\n");
                                    System.out.println("Payload header:\t" + payload.toString());
                                    payload1 = "Payload header:\t" + payload.toString();

                                    //jTextArea2.append("Payload:\n" + "\n" + "Payload header:\t" + payload.toString() + "\n");
                                }

                                data1 = "TCP src port:\t" + tcp.source() + "\n" + "TCP dst port:\t" + tcp.destination() + "\n" + "Tcp acknowledge:\t" + tcp.ack() + "\n" + "Tcp header:\t" + tcp.toString() + "\n";
                                Packet p1 = new Packet(index, data1, payload1);

                            } else if (packet.hasHeader(udp)) {

                                index = j++;
                                rowData2[0] = index;
                                rowData2[1] = udp.source();
                                rowData2[2] = udp.destination();
                                rowData2[3] = "UDP";
                                model2.addRow(rowData2);
                                System.out.println("UDP src port:\t" + udp.source());
                                System.out.println("UDP dst port:\t" + udp.destination());
                                System.out.println("UDP Checksum:\t" + udp.checksum());

                                System.out.println("UDP header:\t" + udp.toString());

                                if (packet.hasHeader(payload)) {
                                    payloadContent = payload.getPayload();
                                    System.out.println("Payload:\n");
                                    System.out.println("Payload header:\t" + payload.toString());
                                    payload1 = "Payload header:\t" + payload.toString();

                                }

                                data1 = "UDP src port:\t" + udp.source() + "\n" + "UDP dst port:\t" + udp.destination() + "\n" + "UDP Checksum:\t" + udp.checksum() + "\n" + "UDP header:\t" + udp.toString() + "\n";
                                Packet p1 = new Packet(index, data1, payload1);
                                l.add(p1);

                            }
                            if (readdata == true) {
                                System.out.println("-\t-\t-\t-\t-");
                            }
                            readdata = false;
                        }
                    };

                    pcap.loop(-1, pcappackethandler, "pressure");

                    pcap.close();

                }
            }

        });

        thread.start();

    }//GEN-LAST:event_jButton1ActionPerformed


    private void jTextField2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField2ActionPerformed

    }//GEN-LAST:event_jTextField2ActionPerformed

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed

        String dev = jTextField2.getText();
        s = Integer.parseInt(dev);
        device = alldevs.get(s); // Get first device in list

        if (device.getDescription() != null) {
            // JOptionPane.showMessageDialog(this, "\nChoosing '%s' on your behalf:\n" + device.getDescription());
            System.out.printf("\nChoosing '%s' on your behalf:\n",
                    (device.getDescription() != null) ? device.getDescription()
                    : device.getName());
        } else {
            JOptionPane.showMessageDialog(this, "No Devices Found");
        }


    }//GEN-LAST:event_jButton4ActionPerformed

    private void jButton5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton5ActionPerformed

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {

            JOptionPane.showMessageDialog(this, "Can't read list of devices, error is %s" + errbuf.toString());
            return;
        }

        int i = 0;
        Object rowData1[] = new Object[3];
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";

            rowData1[0] = i++;
            rowData1[1] = device.getName();
            rowData1[2] = description;
            model1.addRow(rowData1);
        }


    }//GEN-LAST:event_jButton5ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        System.exit(0);
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton7ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton7ActionPerformed

        l.clear();
        index = 0;
        String fileName = jTextField3.getText();
        final String FILENAME = fileName + ".cap";
        pcap = Pcap.openOffline(FILENAME, errbuf);
        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        pcap.loop(-1, new JPacketHandler<StringBuilder>() {

            public void nextPacket(JPacket packet, StringBuilder errbuf) {

                byte[] data = packet.getByteArray(0, packet.size());
                byte[] sIP = new byte[4];
                byte[] dIP = new byte[4];

                String data1 = "";
                String payload1 = "";

                if (packet.hasHeader(ip)) {
                    sIP = ip.source();
                    dIP = ip.destination();

                    String sourceIP
                            = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    String destinationIP
                            = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    String type = Integer.toHexString(ip.type());

                    index = j++;
                    rowData2[0] = index;
                    rowData2[1] = sourceIP;
                    rowData2[2] = destinationIP;
                    rowData2[3] = "IP";
                    model2.addRow(rowData2);

                    System.out.println("srcIP=" + sourceIP
                            + " dstIP=" + destinationIP
                            + " caplen=" + packet.getCaptureHeader().caplen() + "type= " + type);
                    System.out.println("IP checksum:\t" + ip.checksum());

                    System.out.println("IP header:\t" + ip.toString());

                    if (packet.hasHeader(payload)) {
                        payloadContent = payload.getPayload();
                        System.out.println("Payload:\n");
                        System.out.println("Payload header:\t" + payload.toString());
                        payload1 = "Payload header:\t" + payload.toString();

                    }

                    data1 = "srcIP=" + sourceIP + "\n" + " dstIP=" + destinationIP + "\n" + " caplen=" + packet.getCaptureHeader().caplen() + "type= " + type + "\n" + "IP checksum:\t" + ip.checksum() + "\n" + "IP header:\t" + ip.toString();

                    Packet p1 = new Packet(index, data1, payload1);
                    l.add(p1);
                }
                if (packet.hasHeader(eth)) {

                    index = j++;
                    rowData2[0] = index;
                    rowData2[1] = FormatUtils.mac(eth.source());
                    rowData2[2] = FormatUtils.mac(eth.destination());
                    rowData2[3] = "ETH";
                    model2.addRow(rowData2);

                    System.out.println("Ethernet type:\t" + eth.typeEnum());
                    System.out.println("Ethernet src:\t" + FormatUtils.mac(eth.source()));
                    System.out.println("Ethernet dst:\t" + FormatUtils.mac(eth.destination()));
                    String hexdump = packet.toHexdump(packet.size(), false, false, true);

                    if (packet.hasHeader(payload)) {
                        payloadContent = payload.getPayload();
                        System.out.println("Payload:\n");
                        System.out.println("Payload header:\t" + payload.toString());
                        payload1 = "Payload header:\t" + payload.toString();

                    }

                    data1 = "Ethernet type:\t" + eth.typeEnum() + "\n" + "Ethernet src:\t" + FormatUtils.mac(eth.source()) + "\n" + "Ethernet dst:\t" + FormatUtils.mac(eth.destination()) + "\n";

                    Packet p1 = new Packet(index, data1, payload1);
                    l.add(p1);

                    data = FormatUtils.toByteArray(hexdump);

                    JMemory packet2 = new JMemoryPacket(JProtocol.ETHERNET_ID, data);

                }
                if (packet.hasHeader(tcp)) {

                    index = j++;
                    rowData2[0] = index;
                    rowData2[1] = tcp.source();
                    rowData2[2] = tcp.destination();
                    rowData2[3] = "TCP";
                    model2.addRow(rowData2);

                    System.out.println("TCP src port:\t" + tcp.source());
                    System.out.println("TCP dst port:\t" + tcp.destination());
                    System.out.println("Tcp acknowledge:\t" + tcp.ack());

                    System.out.println("Tcp header:\t" + tcp.toString());

                    if (packet.hasHeader(payload)) {
                        payloadContent = payload.getPayload();
                        System.out.println("Payload:\n");
                        System.out.println("Payload header:\t" + payload.toString());
                        payload1 = "Payload header:\t" + payload.toString();

                    }

                    data1 = "TCP src port:\t" + tcp.source() + "\n" + "TCP dst port:\t" + tcp.destination() + "\n" + "Tcp acknowledge:\t" + tcp.ack() + "\n" + "Tcp hearer:\t" + tcp.toString() + "\n";
                    Packet p1 = new Packet(index, data1, payload1);
                    l.add(p1);

                } else if (packet.hasHeader(udp)) {

                    index = j++;
                    rowData2[0] = index;
                    rowData2[1] = udp.source();
                    rowData2[2] = udp.destination();
                    rowData2[3] = "UDP";
                    model2.addRow(rowData2);

                    System.out.println("UDP src port:\t" + udp.source());
                    System.out.println("UDP dst port:\t" + udp.destination());
                    System.out.println("UDP Checksum:\t" + udp.checksum());

                    System.out.println("UDP header:\t" + udp.toString());

                    if (packet.hasHeader(payload)) {
                        payloadContent = payload.getPayload();
                        System.out.println("Payload:\n");
                        System.out.println("Payload header:\t" + payload.toString());
                        payload1 = "Payload header:\t" + payload.toString();

                    }

                    data1 = "UDP src port:\t" + udp.source() + "\n" + "UDP dst port:\t" + udp.destination() + "\n" + "UDP Checksum:\t" + udp.checksum() + "\n" + "UDP header:\t" + udp.toString() + "\n";

                    Packet p1 = new Packet(index, data1, payload1);
                    l.add(p1);
                }

                if (readdata == true) {
                    System.out.println("-\t-\t-\t-\t-");
                }
                readdata = false;
            }
        }, errbuf);


    }//GEN-LAST:event_jButton7ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        flag = false;
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jTextField4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField4ActionPerformed

    }//GEN-LAST:event_jTextField4ActionPerformed

    private void jButton8ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton8ActionPerformed
        String ofile = jTextField4.getText();
        if (ofile != null) {
            PcapDumper dumper = pcap.dumpOpen(ofile + ".pcap");

            pcap.loop(-1, dumper);

            File file = new File(ofile);
            System.out.printf("%s file has %d bytes in it!\n", ofile + ".pcap", file.length());

            dumper.close();
        }
    }//GEN-LAST:event_jButton8ActionPerformed

    private void jTable1MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jTable1MouseClicked

        int index = jTable1.getSelectedRow();
        int value1 = Integer.parseInt(model2.getValueAt(index, 0).toString());

        for (int i = 0; i < l.size(); i++) {
            if (value1 == l.get(i).index) {
                jTextArea1.setText(l.get(i).data);
                jTextArea2.setText(l.get(i).payload);
            }
        }
    }//GEN-LAST:event_jTable1MouseClicked

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(NewJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(NewJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(NewJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(NewJFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new NewJFrame().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButton5;
    private javax.swing.JButton jButton7;
    private javax.swing.JButton jButton8;
    private javax.swing.JButton jButton9;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JTable jTable1;
    private javax.swing.JTable jTable2;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextArea jTextArea2;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    private javax.swing.JTextField jTextField4;
    // End of variables declaration//GEN-END:variables
}
