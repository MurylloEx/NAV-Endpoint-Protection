using System;
using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;
using SharpPcap.LibPcap;
using SharpPcap.WinDivert;

namespace NavNetFilter
{

    public delegate void TcpPacketIncoming(object sender, TCP_PACKET_STRUCTURE args);
    public delegate void UdpPacketIncoming(object sender, UDP_PACKET_STRUCTURE args);
    public delegate void IcmpV4PacketIncoming(object sender, ICMPV4_PACKET_STRUCTURE args);
    public delegate void IcmpV6PacketIncoming(object sender, ICMPV6_PACKET_STRUCTURE args);
    public delegate void IgmpV2PacketIncoming(object sender, IGMPV2_PACKET_STRUCTURE args);

    public delegate void PcapDriverStartedEvent(object sender, object args);
    public delegate void PcapDriverStoppedEvent(object sender, object args);

    public struct TCP_PACKET_STRUCTURE
    {
        public EthernetPacket EthernetPackerPtr { get; set; }
        public IPPacket IpPacketPtr { get; set; }
        public TcpPacket TcpPacketPtr { get; set; }
    }

    public struct UDP_PACKET_STRUCTURE
    {
        public EthernetPacket EthernetPackerPtr { get; set; }
        public IPPacket IpPacketPtr { get; set; }
        public UdpPacket UdpPacketPtr { get; set; }
    }

    public struct ICMPV4_PACKET_STRUCTURE
    {
        public EthernetPacket EthernetPackerPtr { get; set; }
        public IPPacket IpPacketPtr { get; set; }
        public IcmpV4Packet IcmpV4PacketPtr { get; set; }
    }

    public struct ICMPV6_PACKET_STRUCTURE
    {
        public EthernetPacket EthernetPackerPtr { get; set; }
        public IPPacket IpPacketPtr { get; set; }
        public IcmpV6Packet IcmpV6PacketPtr { get; set; }
    }

    public struct IGMPV2_PACKET_STRUCTURE
    {
        public EthernetPacket EthernetPackerPtr { get; set; }
        public IPPacket IpPacketPtr { get; set; }
        public IgmpV2Packet IgmpV2PacketPtr { get; set; }
    }

    class PacketCaptureDriver
    {

        public event TcpPacketIncoming OnTcpPacketIncoming = (s, e) => { };
        public event UdpPacketIncoming OnUdpPacketIncoming = (s, e) => { };
        public event IcmpV4PacketIncoming OnIcmpV4PacketIncoming = (s, e) => { };
        public event IcmpV6PacketIncoming OnIcmpV6PacketIncoming = (s, e) => { };
        public event IgmpV2PacketIncoming OnIgmpV2PacketIncoming = (s, e) => { };

        public event PcapDriverStartedEvent PacketCaptureDriverStarted = (s, e) => { };
        public event PcapDriverStoppedEvent PacketCaptureDriverStopped = (s, e) => { };

        private ICaptureDevice CaptureDevice;

        public PacketCaptureDriver(ICaptureDevice capDevice)
        {
            capDevice.OnPacketArrival += CapDevice_OnPacketArrival;
            capDevice.OnCaptureStopped += CapDevice_OnCaptureStopped;
            if (capDevice is NpcapDevice)
            {
                NpcapDevice npcap = (NpcapDevice)capDevice;
                npcap.Open(DeviceMode.Normal, 2000);
            }
            else if (capDevice is WinDivertDevice)
            {
                WinDivertDevice windivert = (WinDivertDevice)capDevice;
                windivert.Open(DeviceMode.Normal, 2000);
            }
            else if (capDevice is LibPcapLiveDevice)
            {
                LibPcapLiveDevice libpcap = (LibPcapLiveDevice)capDevice;
                libpcap.Open(DeviceMode.Normal, 2000);
            }
            else
            {
                throw new NotSupportedException("The driver cannot connect to any capture device.");
            }
            CaptureDevice = capDevice;
        }

        ~PacketCaptureDriver()
        {
            CaptureDevice = null;
        }

        public void StartCapture()
        {
            CaptureDevice.StartCapture();
            PacketCaptureDriverStarted(CaptureDevice, null);
        }

        public void StopCapture()
        {
            CaptureDevice.StopCapture();
        }

        private void CapDevice_OnCaptureStopped(object sender, CaptureStoppedEventStatus status)
        {
            PacketCaptureDriverStarted(sender, status);
        }

        private void CapDevice_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            Packet payload = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if (payload is EthernetPacket)
            {
                EthernetPacket ethPacket = (EthernetPacket)payload;
                IPPacket ipPacket = ethPacket.Extract<IPPacket>();
                if (ipPacket != null)
                {
                    TcpPacket tcpPacket = ethPacket.Extract<TcpPacket>();
                    if (tcpPacket != null)
                    {
                        TCP_PACKET_STRUCTURE tcpStruct = new TCP_PACKET_STRUCTURE()
                        {
                            EthernetPackerPtr = ethPacket,
                            IpPacketPtr = ipPacket,
                            TcpPacketPtr = tcpPacket
                        };
                        OnTcpPacketIncoming(this, tcpStruct);
                        return;
                    }
                    UdpPacket udpPacket = ethPacket.Extract<UdpPacket>();
                    if (udpPacket != null)
                    {
                        UDP_PACKET_STRUCTURE udpStruct = new UDP_PACKET_STRUCTURE()
                        {
                            EthernetPackerPtr = ethPacket,
                            IpPacketPtr = ipPacket,
                            UdpPacketPtr = udpPacket
                        };
                        OnUdpPacketIncoming(this, udpStruct);
                        return;
                    }
                    IcmpV4Packet icmpv4Packet = ethPacket.Extract<IcmpV4Packet>();
                    if (icmpv4Packet != null)
                    {
                        ICMPV4_PACKET_STRUCTURE icmpv4Struct = new ICMPV4_PACKET_STRUCTURE()
                        {
                            EthernetPackerPtr = ethPacket,
                            IpPacketPtr = ipPacket,
                            IcmpV4PacketPtr = icmpv4Packet
                        };
                        OnIcmpV4PacketIncoming(this, icmpv4Struct);
                        return;
                    }
                    IcmpV6Packet icmpv6Packet = ethPacket.Extract<IcmpV6Packet>();
                    if (icmpv6Packet != null)
                    {
                        ICMPV6_PACKET_STRUCTURE icmpv6Struct = new ICMPV6_PACKET_STRUCTURE()
                        {
                            EthernetPackerPtr = ethPacket,
                            IpPacketPtr = ipPacket,
                            IcmpV6PacketPtr = icmpv6Packet
                        };
                        OnIcmpV6PacketIncoming(this, icmpv6Struct);
                        return;
                    }
                    IgmpV2Packet igmpv2Packet = ethPacket.Extract<IgmpV2Packet>();
                    if (igmpv2Packet != null)
                    {
                        IGMPV2_PACKET_STRUCTURE igmpv2Struct = new IGMPV2_PACKET_STRUCTURE()
                        {
                            EthernetPackerPtr = ethPacket,
                            IpPacketPtr = ipPacket,
                            IgmpV2PacketPtr = igmpv2Packet
                        };
                        OnIgmpV2PacketIncoming(this, igmpv2Struct);
                        return;
                    }
                }
            }
        }

    }
}
