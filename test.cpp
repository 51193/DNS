#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <pcap.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")

// 打开网卡返回的指针
pcap_t *m_adhandle;
unsigned char *FinalPacket;
unsigned int UserDataLen;

// 通过传入本机IP地址打开网卡
void OpenAdapter(std::string local_address)
{
    pcap_if_t *alldevs = NULL, *d = NULL;
    char errbuf[256] = {0};
    bpf_program fcode;
    u_int netmask;

    // 获取网卡设备指针
    if (-1 == pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf))
    {
        std::cout << "获取网卡设备指针出错" << std::endl;
        return;
    }

    // 选取适合网卡
    int flag = 0;
    for (d = alldevs; d; d = d->next)
    {
        pcap_addr_t *p = d->addresses;
        while (p)
        {
            if (local_address == inet_ntoa(((sockaddr_in *)p->addr)->sin_addr))
            {
                flag = 1;
                break;
            }
            p = p->next;
        }
        if (1 == flag)
            break;
    }
    if (0 == flag)
    {
        std::cout << "请检查本机IP地址是否正确" << std::endl;
        std::cout << local_address.c_str() << std::endl;
        return;
    }

    // 获取子网掩码
    netmask = ((sockaddr_in *)d->addresses->netmask)->sin_addr.S_un.S_addr;

    // 打开网卡
    m_adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (NULL == m_adhandle)
    {
        std::cout << "打开网卡出错" << std::endl;
        pcap_freealldevs(alldevs);
        return;
    }

    // 检查以太网
    if (DLT_EN10MB != pcap_datalink(m_adhandle))
    {
        std::cout << "此程序仅在以太网下工作" << std::endl;
        pcap_freealldevs(alldevs);
        return;
    }

    // 释放网卡设备列表
    pcap_freealldevs(alldevs);
}

// MAC地址转Bytes
unsigned char *MACStringToBytes(std::string String)
{
    // 获取输入字符串的长度
    int iLen = strlen(String.c_str());

    // 创建一个临时缓冲区，用于存储输入字符串的拷贝
    char *Tmp = new char[(iLen + 1)];

    // 将输入字符串拷贝到临时缓冲区
    strcpy(Tmp, String.c_str());

    // 创建一个用于存储结果的unsigned char数组，数组大小为6
    unsigned char *Returned = new unsigned char[6];

    // 循环处理每个字节
    for (int i = 0; i < 6; i++)
    {
        // 使用sscanf将字符串中的两个字符转换为16进制数，存储到Returned数组中
        sscanf(Tmp, "%2X", &Returned[i]);

        // 移动临时缓冲区的指针，跳过已经处理过的字符
        memmove((void *)(Tmp), (void *)(Tmp + 3), 19 - i * 3);
    }

    // 返回存储结果的数组
    return Returned;
}

// Bytes地址转16进制
unsigned short BytesTo16(unsigned char X, unsigned char Y)
{
    // 将 X 左移8位，然后与 Y 进行按位或操作，得到一个16位的无符号整数
    unsigned short Tmp = X;
    Tmp = Tmp << 8;
    Tmp = Tmp | Y;
    return Tmp;
}

// 计算IP校验和
unsigned short CalculateIPChecksum(UINT TotalLen, UINT ID, UINT SourceIP, UINT DestIP)
{
    // 初始化校验和
    unsigned short CheckSum = 0;

    // 遍历 IP 头的每两个字节
    for (int i = 14; i < 34; i += 2)
    {
        // 将每两个字节合并为一个16位整数
        unsigned short Tmp = BytesTo16(FinalPacket[i], FinalPacket[i + 1]);

        // 计算校验和
        unsigned short Difference = 65535 - CheckSum;
        CheckSum += Tmp;

        // 处理溢出
        if (Tmp > Difference)
        {
            CheckSum += 1;
        }
    }

    // 取反得到最终的校验和
    CheckSum = ~CheckSum;

    return CheckSum;
}

// 计算UDP校验和
unsigned short CalculateUDPChecksum(unsigned char *UserData, int UserDataLen, UINT SourceIP, UINT DestIP, USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol)
{
    unsigned short CheckSum = 0;

    // 计算 UDP 数据报的伪首部长度
    unsigned short PseudoLength = UserDataLen + 8 + 9; // 长度包括 UDP 头（8字节）和伪首部（9字节）

    // 如果长度不是偶数，添加一个额外的字节
    PseudoLength += PseudoLength % 2;

    // 创建 UDP 伪首部
    unsigned char *PseudoHeader = new unsigned char[PseudoLength];
    RtlZeroMemory(PseudoHeader, PseudoLength);

    // 设置伪首部中的协议字段为 UDP (0x11)
    PseudoHeader[0] = 0x11;

    // 复制源和目标 IP 地址到伪首部
    memcpy((void *)(PseudoHeader + 1), (void *)(FinalPacket + 26), 8);

    // 将 UDP 头的长度字段拷贝到伪首部
    unsigned short Length = UserDataLen + 8;
    Length = htons(Length);
    memcpy((void *)(PseudoHeader + 9), (void *)&Length, 2);
    memcpy((void *)(PseudoHeader + 11), (void *)&Length, 2);

    // 将源端口、目标端口和 UDP 数据拷贝到伪首部
    memcpy((void *)(PseudoHeader + 13), (void *)(FinalPacket + 34), 2);
    memcpy((void *)(PseudoHeader + 15), (void *)(FinalPacket + 36), 2);
    memcpy((void *)(PseudoHeader + 17), (void *)UserData, UserDataLen);

    // 遍历伪首部的每两个字节，计算校验和
    for (int i = 0; i < PseudoLength; i += 2)
    {
        unsigned short Tmp = BytesTo16(PseudoHeader[i], PseudoHeader[i + 1]);
        unsigned short Difference = 65535 - CheckSum;
        CheckSum += Tmp;
        if (Tmp > Difference)
        {
            CheckSum += 1;
        }
    }

    // 取反得到最终的校验和
    CheckSum = ~CheckSum;

    // 释放伪首部的内存
    delete[] PseudoHeader;

    return CheckSum;
}

void CreatePacket(unsigned char *SourceMAC, unsigned char *DestinationMAC, unsigned int SourceIP, unsigned int DestIP, unsigned short SourcePort, unsigned short DestinationPort, unsigned char *UserData, unsigned int UserDataLength)
{
    UserDataLen = UserDataLength;
    FinalPacket = new unsigned char[UserDataLength + 42]; // 为数据长度加上42字节的标头保留足够的内存
    USHORT TotalLen = UserDataLength + 20 + 8;            // IP报头使用数据长度加上IP报头长度（通常为20字节）加上udp报头长度（通常为8字节）

    // 开始填充以太网包头
    memcpy((void *)FinalPacket, (void *)DestinationMAC, 6);
    memcpy((void *)(FinalPacket + 6), (void *)SourceMAC, 6);

    USHORT TmpType = 8;
    memcpy((void *)(FinalPacket + 12), (void *)&TmpType, 2); // 使用的协议类型(USHORT）类型0x08是UDP。可以为其他协议（例如TCP）更改此设置

    // 开始填充IP头数据包
    memcpy((void *)(FinalPacket + 14), (void *)"\x45", 1); // 前3位的版本（4）和最后5位的标题长度。
    memcpy((void *)(FinalPacket + 15), (void *)"\x00", 1); // 通常为0
    TmpType = htons(TotalLen);
    memcpy((void *)(FinalPacket + 16), (void *)&TmpType, 2);

    TmpType = htons(0x1337);
    memcpy((void *)(FinalPacket + 18), (void *)&TmpType, 2);   // Identification
    memcpy((void *)(FinalPacket + 20), (void *)"\x00", 1);     // Flags
    memcpy((void *)(FinalPacket + 21), (void *)"\x00", 1);     // Offset
    memcpy((void *)(FinalPacket + 22), (void *)"\x80", 1);     // Time to live.
    memcpy((void *)(FinalPacket + 23), (void *)"\x11", 1);     // 协议UDP为0x11（17）TCP为6 ICMP为1等
    memcpy((void *)(FinalPacket + 24), (void *)"\x00\x00", 2); // 计算校验和
    memcpy((void *)(FinalPacket + 26), (void *)&SourceIP, 4);  // inet_addr does htonl() for us
    memcpy((void *)(FinalPacket + 30), (void *)&DestIP, 4);

    // 开始填充UDP头部数据包
    TmpType = htons(SourcePort);
    memcpy((void *)(FinalPacket + 34), (void *)&TmpType, 2);
    TmpType = htons(DestinationPort);
    memcpy((void *)(FinalPacket + 36), (void *)&TmpType, 2);
    USHORT UDPTotalLen = htons(UserDataLength + 8); // UDP Length does not include length of IP header
    memcpy((void *)(FinalPacket + 38), (void *)&UDPTotalLen, 2);
    // memcpy((void*)(FinalPacket+40),(void*)&TmpType,2); //checksum
    memcpy((void *)(FinalPacket + 42), (void *)UserData, UserDataLength);

    unsigned short UDPChecksum = CalculateUDPChecksum(UserData, UserDataLength, SourceIP, DestIP, htons(SourcePort), htons(DestinationPort), 0x11);
    memcpy((void *)(FinalPacket + 40), (void *)&UDPChecksum, 2);

    unsigned short IPChecksum = htons(CalculateIPChecksum(TotalLen, 0x1337, SourceIP, DestIP));
    memcpy((void *)(FinalPacket + 24), (void *)&IPChecksum, 2);

    return;
}

int main(int argc, char *argv[])
{
    // 打开网卡
    OpenAdapter("10.129.88.199");

    // 填充地址并生成数据包包头
    char SourceMAC[MAX_PATH] = "8C-ff-ff-ff-ff-ff";
    char SourceIP[MAX_PATH] = "192.168.93.11";
    char SourcePort[MAX_PATH] = "80";

    char DestinationMAC[MAX_PATH] = "8C-dd-dd-dd-dd-dd";
    char DestinationIP[MAX_PATH] = "192.168.93.11";
    char DestinationPort[MAX_PATH] = "8080";

    char DataString[MAX_PATH] = "123";
    CreatePacket(MACStringToBytes(SourceMAC), MACStringToBytes(DestinationMAC), inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR *)DataString, (strlen(DataString) + 1));

    // 循环发包
    for (int x = 0; x < 10; x++)
    {
        if (0 != pcap_sendpacket(m_adhandle, FinalPacket, (UserDataLen + 42)))
        {
            char *szErr = pcap_geterr(m_adhandle);
            return 0;
        }
    }

    system("pause");
    return 0;
}