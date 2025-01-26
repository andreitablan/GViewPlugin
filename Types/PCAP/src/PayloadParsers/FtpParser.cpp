#include "FtpParser.hpp"
#include <PCAP.hpp>
using namespace GView::Type::PCAP;
constexpr uint32 maxWaitUntilEndLine         = 300;
constexpr std::string_view ftpWelcomePattern = "220 ";
constexpr std::string_view ftpCommandPattern = "USER ";

PayloadDataParserInterface* FTP::FTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    const auto connPayload = payloadInformation.payload;
    if (connPayload->size < 10)
        return nullptr;
    if (memcmp(payloadInformation.payload->location, "220 ", 3) != 0)
        return nullptr;

    auto& applicationLayers      = callbackInterface->GetApplicationLayers();
    StreamTcpLayer summaryLayer  = {};
    StreamTcpLayer detailedLayer = {};

    std::ostringstream detailedInfo;
    std::map<std::string, std::string> ftpKeyValueMap;
    detailedInfo << "FTP Packet Analysis:\n";
    uint32 packetCount = 0, layerCount = 0;

    for (auto& packet : *payloadInformation.packets) {
        packetCount++;
        detailedInfo << "\nIndex Packet: " << packetCount << "\n";
        detailedInfo << "Packet Info:\n";
        auto formattedTimestamp = packet.header->tsSec * (uint64) 1000000 + packet.header->tsUsec;
        formattedTimestamp /= 1000000;
        AppCUI::OS::DateTime dt;
        dt.CreateFromTimestamp(formattedTimestamp);
        detailedInfo << "  Timestamp: " << dt.GetStringRepresentation().data() << "\n";
        detailedInfo << "  Captured Length: " << packet.header->inclLen << " bytes\n";
        detailedInfo << "  Original Length: " << packet.header->origLen << " bytes\n";
        LocalString<64> srcIp, dstIp, srcPort, dstPort;
        NumericFormatter n;
        if (packet.packetData.linkLayer.has_value()) {
            auto* ipv4   = (IPv4Header*) packet.packetData.linkLayer->header;
            auto ipv4Ref = *ipv4;

            detailedInfo << "Ethernet Header:\n";
            Swap(ipv4Ref);

            Utils::IPv4ElementToStringNoHex(ipv4Ref.sourceAddress, srcIp);
            Utils::IPv4ElementToStringNoHex(ipv4Ref.destinationAddress, dstIp);

            detailedInfo << "  IPv4 Source: " << srcIp << "\n";
            detailedInfo << "  IPv4 Destination: " << dstIp << "\n";
        }

        if (packet.packetData.transportLayer.has_value() && packet.packetData.transportLayer->transportLayer == IP_Protocol::TCP) {
            auto tcp = (TCPHeader*) packet.packetData.transportLayer->transportLayerHeader;
            detailedInfo << "TCP Header:\n";
            auto tcpRef = *tcp;
            srcPort.Format("%s", n.ToString(tcpRef.sPort, { NumericFormatFlags::None, 10, 3, '.' }).data());
            dstPort.Format("%s", n.ToString(tcpRef.dPort, { NumericFormatFlags::None, 10, 3, '.' }).data());

            detailedInfo << "  Source Port: " << srcPort << "\n";
            detailedInfo << "  Destination Port: " << dstPort << "\n";
        }

        if (packet.payload.size > 0) {
            detailedInfo << "FTP Data Packet:\n";
            detailedInfo << "  Payload Size: " << packet.payload.size << " bytes\n";
        }
        if (packet.payload.size > 0) {
            std::string ftpMessage(reinterpret_cast<const char*>(packet.payload.location), packet.payload.size);
            detailedInfo << "FTP Payload: " << ftpMessage << "\n";

            std::istringstream ftpStream(ftpMessage);
            std::string line;
            while (std::getline(ftpStream, line)) {
                size_t delimiterPos = line.find(' ');
                if (delimiterPos != std::string::npos) {
                    std::string key   = line.substr(0, delimiterPos);
                    std::string value = line.substr(delimiterPos + 1);
                    ftpKeyValueMap.insert({ key, value });
                }
            }
        }
    }

    detailedInfo << "\nSummary:\n";
    detailedInfo << "  Total Packets: " << packetCount << "\n";
    detailedInfo << "  Layers Processed: " << layerCount << "\n";

    std::ostringstream tableInfo;

    if (!ftpKeyValueMap.empty()) {
        tableInfo << "-----------------------------------------\n\n";

        tableInfo << "Parsed FTP Key-Value Map (Table Format):\n";

        for (const auto& [key, value] : ftpKeyValueMap) {
            tableInfo << std::setw(20) << std::left << key << std::setw(15) << std::left << value << "\n";
        }

        tableInfo << "-----------------------------------------\n\n";
    }

    std::string originalInfo = detailedInfo.str();
    detailedInfo.str("");
    detailedInfo.clear();

    detailedInfo << tableInfo.str();
    detailedInfo << originalInfo;

    std::string dataStr = detailedInfo.str();

    const char* summaryText = "FTP Connection Established";
    summaryLayer.name       = std::make_unique<uint8[]>(strlen(summaryText) + 1);
    memcpy(summaryLayer.name.get(), summaryText, strlen(summaryText) + 1);
    applicationLayers.emplace_back(std::move(summaryLayer));

    const char* detailedText = "Detailed FTP Information";
    detailedLayer.name       = std::make_unique<uint8[]>(strlen(detailedText) + 1);
    memcpy(detailedLayer.name.get(), detailedText, strlen(detailedText) + 1);
    detailedLayer.payload.size     = dataStr.size() + 1;
    detailedLayer.payload.location = new uint8[detailedLayer.payload.size];
    memcpy(detailedLayer.payload.location, dataStr.c_str(), detailedLayer.payload.size);
    applicationLayers.emplace_back(std::move(detailedLayer));

    std::ostringstream conciseSummary;
    conciseSummary << "FTP Packet Analysis: " << packetCount << " packets captured.";
    callbackInterface->AddConnectionSummary(conciseSummary.str());
    callbackInterface->AddConnectionAppLayerName("FTP");

    return this;
}