
namespace NavNetFilter
{
    public struct DnsQuery {

        public DnsQuery(ref byte[] packetData)
        {
            DomainName = null;
            DomainNameLength = 0;
            QueryType = 0;
            QueryClass = 0;
        }

        public string DomainName { set; get; }

        public ushort DomainNameLength { set; get; }

        public ushort QueryType { set; get; }

        public ushort QueryClass { set; get; }

    }
}
