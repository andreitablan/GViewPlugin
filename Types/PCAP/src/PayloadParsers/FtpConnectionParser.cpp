
#include "FtpConnectionParser.hpp"
#include <PCAP.hpp>

using namespace GView::Type::PCAP;
constexpr uint32 maxWaitUntilEndLine         = 300;
constexpr std::string_view ftpWelcomePattern = "220 ";
constexpr std::string_view ftpCommandPattern = "USER ";

PayloadDataParserInterface* FTPConnectionParser::FTPConnectionParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{

    auto& applicationLayers = callbackInterface->GetApplicationLayers();
    callbackInterface->AddConnectionAppLayerName("FTPConnection");
    return this;
}

