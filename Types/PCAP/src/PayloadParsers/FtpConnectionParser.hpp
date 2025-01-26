#pragma once

#include "API.hpp"

namespace GView::Type::PCAP::FTPConnectionParser
{

struct FTPConnectionParser : public PayloadDataParserInterface {
    std::string GetProtocolName() const override
    {
        return "FTPConnection";
    }

    PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) override;
};
} // namespace GView::Type::PCAP::FTP

