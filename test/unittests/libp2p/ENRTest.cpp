// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include <libp2p/ENR.h>
#include <gtest/gtest.h>

using namespace dev;
using namespace dev::p2p;

namespace
{
bytes dummySignFunction(bytesConstRef)
{
    return {};
}
bool dummyVerifyFunction(std::map<std::string, bytes> const&, bytesConstRef, bytesConstRef)
{
    return true;
};
}  // namespace

TEST(enr, createAndParse)
{
    auto keyPair = KeyPair::create();

    ENR enr1 = createV4ENR(keyPair.secret(), bi::address::from_string("127.0.0.1"), 3322, 5544);

    RLPStream s;
    enr1.streamRLP(s);
    bytes rlp = s.out();

    ENR enr2 = parseV4ENR(RLP{rlp});

    EXPECT_EQ(enr1.signature(), enr2.signature());
    EXPECT_EQ(enr1.sequenceNumber(), enr2.sequenceNumber());
    EXPECT_EQ(enr1.keyValues(), enr2.keyValues());
}

TEST(enr, parseTooBigRlp)
{
    std::map<std::string, bytes> keyValues = {{"key", rlp(bytes(300, 'a'))}};

    ENR enr1{0, keyValues, dummySignFunction};

    RLPStream s;
    enr1.streamRLP(s);
    bytes rlp = s.out();

    EXPECT_THROW(ENR(RLP(rlp), dummyVerifyFunction), ENRIsTooBig);
}

TEST(enr, parseKeysNotSorted)
{
    std::vector<std::pair<std::string, bytes>> keyValues = {{"keyB", RLPNull}, {"keyA", RLPNull}};

    RLPStream s((keyValues.size() * 2 + 2));
    s << bytes{};  // signature
    s << 0;        // sequence number
    for (auto const keyValue : keyValues)
    {
        s << keyValue.first;
        s.appendRaw(keyValue.second);
    }
    bytes rlp = s.out();

    EXPECT_THROW(ENR(RLP(rlp), dummyVerifyFunction), ENRKeysAreNotUniqueSorted);
}

TEST(enr, parseKeysNotUnique)
{
    std::vector<std::pair<std::string, bytes>> keyValues = {{"key", RLPNull}, {"key", RLPNull}};

    RLPStream s((keyValues.size() * 2 + 2));
    s << bytes{};  // signature
    s << 0;        // sequence number
    for (auto const keyValue : keyValues)
    {
        s << keyValue.first;
        s.appendRaw(keyValue.second);
    }
    bytes rlp = s.out();

    EXPECT_THROW(ENR(RLP(rlp), dummyVerifyFunction), ENRKeysAreNotUniqueSorted);
}

TEST(enr, parseInvalidSignature)
{
    auto keyPair = KeyPair::create();

    ENR enr1 = createV4ENR(keyPair.secret(), bi::address::from_string("127.0.0.1"), 3322, 5544);

    RLPStream s;
    enr1.streamRLP(s);
    bytes rlp = s.out();

    // change one byte of a signature
    auto signatureOffset = RLP{rlp}[0].payload().data() - rlp.data();
    rlp[signatureOffset]++;

    EXPECT_THROW(parseV4ENR(RLP{rlp}), ENRSignatureIsInvalid);
}

TEST(enr, createV4)
{
    auto keyPair = KeyPair::create();
    ENR enr = createV4ENR(keyPair.secret(), bi::address::from_string("127.0.0.1"), 3322, 5544);

    auto keyValues = enr.keyValues();

    EXPECT_TRUE(contains(keyValues, std::string("id")));
    EXPECT_TRUE(contains(keyValues, std::string("sec256k1")));
    EXPECT_TRUE(contains(keyValues, std::string("ip")));
    EXPECT_TRUE(contains(keyValues, std::string("tcp")));
    EXPECT_TRUE(contains(keyValues, std::string("udp")));
}
