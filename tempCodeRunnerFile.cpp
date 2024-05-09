#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <string>
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
    // 使用的协议类型(USHORT）类型0x08是UDP。可以为其他协议（例如TCP）更改此设置
    memcpy((void *)(FinalPacket + 12), (void *)&TmpType, 2);

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
    USHORT UDPTotalLen = htons(UserDataLength + 8); // UDP长度不包括IP包头长度
    memcpy((void *)(FinalPacket + 38), (void *)&UDPTotalLen, 2);
    memcpy((void *)(FinalPacket + 42), (void *)UserData, UserDataLength);

    // 计算UDP校验和
    unsigned short UDPChecksum = CalculateUDPChecksum(UserData, UserDataLength, SourceIP, DestIP,
                                                      htons(SourcePort), htons(DestinationPort), 0x11);
    memcpy((void *)(FinalPacket + 40), (void *)&UDPChecksum, 2);

    // 计算IP校验和
    unsigned short IPChecksum = htons(CalculateIPChecksum(TotalLen, 0x1337, SourceIP, DestIP));
    memcpy((void *)(FinalPacket + 24), (void *)&IPChecksum, 2);

    return;
}

// 构造DNS查询的示例
void CreateDNSQuery(unsigned char *UserData, unsigned int &UserDataLength, const char *domain_1, const char *domain_2)
{
    // 设置DNS头部
    UserData[0] = 0x12; // 事务ID高字节
    UserData[1] = 0x34; // 事务ID低字节
    UserData[2] = 0x01; // 标准查询
    UserData[3] = 0x00;
    UserData[4] = 0x00; // 问题数高字节
    UserData[5] = 0x01; // 问题数低字节
    UserData[6] = 0x00; // 答案资源记录数 = 0
    UserData[7] = 0x00;
    UserData[8] = 0x00; // 授权资源记录数 = 0
    UserData[9] = 0x00;
    UserData[10] = 0x00; // 额外资源记录数 = 0
    UserData[11] = 0x00;

    // 添加查询名称
    int index = 12;                       // 当前UserData的索引
    UserData[index++] = strlen(domain_1); // 二级域名长度
    memcpy(UserData + index, domain_1, strlen(domain_1));
    index += strlen(domain_1);
    UserData[index++] = strlen(domain_2); // 一级域名长度
    memcpy(UserData + index, domain_2, strlen(domain_2));
    index += strlen(domain_2);
    UserData[index++] = 0x00; // 结束标志

    // 设置查询类型和查询类
    UserData[index++] = 0x00;
    UserData[index++] = 0x01; // A记录类型
    UserData[index++] = 0x00;
    UserData[index++] = 0x01; // IN类

    UserDataLength = index; // 更新UserDataLength
}

int frequency = 0;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    pcap_dumper_t *dumper = (pcap_dumper_t *)param;
    pcap_dump((unsigned char *)dumper, header, pkt_data);
    // Ethernet头部长度固定为14字节
    const int ETHERNET_HEADER_LENGTH = 14;
    // IP头部长度最小20字节，但可能包含选项
    const int IP_HEADER_LENGTH = 20;
    // UDP头部长度固定为8字节
    const int UDP_HEADER_LENGTH = 8;
    // DNS事务ID位于DNS部分的起始处，因此偏移量为 IP头部长度 + UDP头部长度
    const int DNS_TRANSACTION_ID_OFFSET = ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH + UDP_HEADER_LENGTH;

    // 确保数据包长度足够包含DNS事务ID
    if (header->len >= DNS_TRANSACTION_ID_OFFSET + 2)
    {
        // 获取DNS事务ID
        unsigned short transaction_id = ntohs(*(unsigned short *)(pkt_data + DNS_TRANSACTION_ID_OFFSET));

        // 检查事务ID是否匹配
        if (transaction_id == 0x1234)
        {
            frequency++;
            if (frequency > 1)
            {
                std::cout << "Received expected DNS response with transaction ID: " << std::hex << transaction_id << std::endl;
                system("pause");
                pcap_breakloop(m_adhandle);
            }
        }
    }
}

#include <Windows.h>

void GetWindowsTimestamp(struct timeval *tv)
{
    FILETIME ft;
    unsigned __int64 tmpres = 0;

    if (NULL != tv)
    {
        GetSystemTimeAsFileTime(&ft);

        tmpres |= ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;

        // 转换file time从1601年1月1日至1970年1月1日的100纳秒单位
        tmpres -= 116444736000000000ULL; // 修改为ULL后缀
        // 转换为微秒
        tmpres /= 10;

        // 转换为秒和微秒
        tv->tv_sec = (long)(tmpres / 1000000ULL);  // 修改为ULL后缀
        tv->tv_usec = (long)(tmpres % 1000000ULL); // 修改为ULL后缀
    }
}

std::map<std::string, std::string> ReadConfig(const std::string &filename)
{
    std::map<std::string, std::string> config;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line))
    {
        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, ':'))
        {
            std::string value;
            if (std::getline(is_line, value))
            {
                config[key] = value.substr(1); // 移除值前的空格
            }
        }
    }

    return config;
}

int main(int argc, char *argv[])
{
    auto config = ReadConfig("config.txt");

    // 读取配置项
    std::string dnsServerIP = config["DNS Server IP"];
    std::string domain1 = config["Domain1"];
    std::string domain2 = config["Domain2"];
    std::string localMAC = config["Local MAC"];
    std::string gatewayMAC = config["Gateway MAC"];
    std::string localIP = config["Local IP"];
    std::string sourcePort = config["Source Port"];

    std::cout << domain1 << '.' << domain2 << std::endl;

    pcap_dumper_t *dumpfile;

    // 打开网卡
    OpenAdapter(localIP);

    // 在打开适配器成功后，添加以下代码
    dumpfile = pcap_dump_open(m_adhandle, "dns_packets.pcap");
    if (dumpfile == NULL)
    {
        std::cerr << "Error opening dump file" << std::endl;
        return 1;
    }

    // 填充地址并生成数据包包头
    char SourceMAC[MAX_PATH];
    strcpy(SourceMAC, localMAC.c_str()); // 使用strcpy函数复制字符串

    char SourceIP[MAX_PATH];
    strcpy(SourceIP, localIP.c_str()); // 使用strcpy函数复制字符串

    char SourcePort[MAX_PATH];
    strcpy(SourcePort, sourcePort.c_str()); // 使用strcpy函数复制字符串

    char DestinationMAC[MAX_PATH];
    strcpy(DestinationMAC, gatewayMAC.c_str()); // 使用strcpy函数复制字符串

    char DestinationIP[MAX_PATH];
    strcpy(DestinationIP, dnsServerIP.c_str()); // 使用strcpy函数复制字符串
    char DestinationPort[MAX_PATH] = "53";

    char Domain1[MAX_PATH];
    strcpy(Domain1, domain1.c_str()); // 使用strcpy函数复制字符串

    char Domain2[MAX_PATH];
    strcpy(Domain2, domain2.c_str()); // 使用strcpy函数复制字符串

    // 准备DNS查询数据
    unsigned char dnsQuery[MAX_PATH]; // 分配足够的空间来构造DNS请求
    unsigned int dnsQueryLength = 0;
    CreateDNSQuery(dnsQuery, dnsQueryLength, Domain1, Domain2);

    // char DataString[MAX_PATH] = "123";
    CreatePacket(MACStringToBytes(SourceMAC), MACStringToBytes(DestinationMAC), inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), dnsQuery, dnsQueryLength);

    if (0 != pcap_sendpacket(m_adhandle, FinalPacket, (dnsQueryLength + 42))) // 注意这里长度的使用
    {
        std::cerr << "发送失败: " << pcap_geterr(m_adhandle) << std::endl;
        return 1;
    }

    std::cout << "DNS request has been sent" << std::endl;

    std::cout << "Starting capture packet" << std::endl;
    if (pcap_loop(m_adhandle, 0, packet_handler, (unsigned char *)dumpfile) < 0)
    {
        std::cerr << "Capture fail: " << pcap_geterr(m_adhandle) << std::endl;
        return -1;
    }

    // 不会执行到这里，除非捕获过程中断
    std::cout << "Capture end" << std::endl;

    // 在程序最后添加资源释放代码
    pcap_dump_close(dumpfile);
    pcap_close(m_adhandle);

    return 0;
}
