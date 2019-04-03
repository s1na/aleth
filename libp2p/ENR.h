// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#pragma once

#include "Common.h"

namespace dev
{
namespace p2p
{
DEV_SIMPLE_EXCEPTION(ENRIsTooBig);
DEV_SIMPLE_EXCEPTION(ENRSignatureIsInvalid);
DEV_SIMPLE_EXCEPTION(ENRKeysAreNotUniqueSorted);

class ENR
{
public:
    using SignFunction = std::function<bytes(bytesConstRef)>;
    using VerifyFunction =
        std::function<bool(std::map<std::string, bytes> const&, bytesConstRef, bytesConstRef)>;

    // parse from RLP with given signature verification function
    ENR(RLP _rlp, VerifyFunction _verifyFunction);
    // create with given sign function
    ENR(uint64_t _seq, std::map<std::string, bytes> const& _keyValues, SignFunction _signFunction);

    uint64_t sequenceNumber() const { return m_seq; }
    std::map<std::string, bytes> const& keyValues() const { return m_map; }
    bytes const& signature() const { return m_signature; }

    void streamRLP(RLPStream& _s) const;

private:
    uint64_t m_seq = 0;
    std::map<std::string, bytes> m_map;
    bytes m_signature;

    bytes content() const;
    size_t contentListSize() const { return m_map.size() * 2 + 1; }
    void streamContent(RLPStream& _s) const;
};


ENR createV4ENR(Secret const& _secret, boost::asio::ip::address const& _ip, uint16_t _tcpPort,  uint16_t _udpPort);

ENR parseV4ENR(RLP _rlp);

std::ostream& operator<<(std::ostream& _out, ENR const& _enr);

}
}
