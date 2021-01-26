using System;
using System.IO;
using System.Collections.Generic;
using PacketDotNet;
using PacketDotNet.Utils.Converters;

namespace NavNetFilter
{
    class DnsQueryPacket : Packet
    {
        byte[] packet;

        public DnsQueryPacket(byte[] packetData) {
            packet = packetData;
        }

        ~DnsQueryPacket() {
            packet = null;
        }

        public short TransactionID {
            get {
                return EndianBitConverter.Big.ToInt16(packet, 0);
            }
        }

        public ushort Flags {
            get {
                return EndianBitConverter.Big.ToUInt16(packet, 2);
            }
        }

        public ushort Questions {
            get {
                return EndianBitConverter.Big.ToUInt16(packet, 4);
            }
        }

        public ushort AnswerRRs {
            get {
                return EndianBitConverter.Big.ToUInt16(packet, 6);
            }
        }

        public ushort AuthorityRRs {
            get {
                return EndianBitConverter.Big.ToUInt16(packet, 8);
            }
        }

        public ushort AdditionalRRs {
            get {
                return EndianBitConverter.Big.ToUInt16(packet, 10);
            }
        }

        public DnsQuery[] Queries {
            get {
                List<DnsQuery> dnsQueries = new List<DnsQuery>();
                try {
                    for (ushort q_idx = 0; q_idx < Questions; q_idx++) {
                        DnsQuery dnsQuery = new DnsQuery();
                        List<Byte> domainBuffer = new List<Byte>();
                        ushort queryType;
                        ushort queryClass;
                        ushort ptr = 0;
                        while (packet[0x0C + q_idx + ptr] != 0x00) {
                            domainBuffer.Add(packet[0x0C + q_idx + ptr++]);
                        }
                        ptr = (ushort)(0x0C + ptr + q_idx);
                        ushort nptr = 0;
                        while (nptr < domainBuffer.Count) {
                            byte labelLength = domainBuffer[nptr];
                            domainBuffer[nptr] = 0x2E;
                            nptr += (ushort)(labelLength+1);
                        }
                        domainBuffer.RemoveAt(0);
                        queryType = EndianBitConverter.Big.ToUInt16(packet, ++ptr);
                        queryClass = EndianBitConverter.Big.ToUInt16(packet, ++ptr + 1);
                        dnsQuery.DomainName = System.Text.Encoding.ASCII.GetString(domainBuffer.ToArray());
                        dnsQuery.DomainNameLength = (ushort)dnsQuery.DomainName.Length;
                        dnsQuery.QueryType = queryType;
                        dnsQuery.QueryClass = queryClass;
                        dnsQueries.Add(dnsQuery);
                    }
                    return dnsQueries.ToArray();
                }
                catch(Exception exception) {
                    throw new InvalidDataException("The UDP packet is malformed! Invalid buffer received for a DNS query.", exception);
                }
            }
        }

    }
}
