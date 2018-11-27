
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <limits.h>
#include <signal.h>

#include <string.h>

#include <string>
#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>

#include <mh/libevent/LibEvent.h>

#include "proxyserver.h"
#include "transaction.h"
#include "concurrentqueue.h"


std::string getMyIp() {
    std::string MyIP;
    const char* statistics_server = "172.104.236.166";
    int statistics_port = 5797;

    struct sockaddr_in serv;

    int sock = socket ( AF_INET, SOCK_STREAM, 0);

    //Socket could not be created
    if (sock < 0)
    {
        perror("Socket error");
    }

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr( statistics_server );
    serv.sin_port = htons( statistics_port );

    connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*) &name, &namelen);

    char buffer[100];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    if (p != nullptr) {
        MyIP = std::string(buffer);
        //        std::cout << MyIP << std::endl;
    } else {
        MyIP = "0.0.0.0";
    }

    close(sock);

    return MyIP;
}


std::string getHostName() {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    return std::string(hostname);
}


bool check_addr(const std::string & addr) {
    if (addr[0] == '0' && addr[1] == 'x') {
        for (uint i = 2; i < addr.length(); i++) {
            if (!isxdigit(addr[i])) {
                std::cout << "Not hex digit: " << addr[i] << "  " << i << std::endl;
                return false;
            }
        }
    } else {
        return false;
    }
    return true;
}


void libevent(moodycamel::ConcurrentQueue<TX *> & send_message, std::string host, int port, KeyManager & key_holder) {
    mh::libevent::LibEvent levent;
    std::string req_post;
    while(true) {
        TX * p_req_post;
        if (send_message.try_dequeue(p_req_post)) {
            req_post.insert(req_post.end(), p_req_post->raw_tx.begin(), p_req_post->raw_tx.end());
            std::string path = key_holder.make_req_url(req_post);

            std::string response;
            while (true) {
                int status = levent.post_keep_alive(host, port, host, path, req_post, response, 500);
                if (status > 0) break;
            }

            delete p_req_post;
            req_post.clear();
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void SIGPIPE_handler(int s) {
    printf("Caught SIGPIPE(%d)\n", s);
}

int main (int argc, char** argv) {
    moodycamel::ConcurrentQueue<TX *> send_message_queue;

    std::cout << "Version:\t" << VESION_MAJOR << "." << VESION_MINOR << "." << std::endl;

    int listen_port = 0;
    int pool_size = 0;
    KeyManager key_holder;
    std::vector<std::thread> sender;

    if (argc > 4) {
        {
            std::ifstream file(argv[1]);
            std::string   line;

            if (std::getline(file, line)) {
                if (!key_holder.parse(line)) {
                    std::cerr << "Error while parsing Private key" << std::endl;
                    std::cerr << "Probably ivalid Private Key File" << std::endl;
                    exit(1);
                }

                std::cout << "got key for address:\t" << key_holder.Text_addres << std::endl;
            } else {
                std::cerr << "Ivalid Private Key File" << std::endl;
                exit(1);
            }
        }

        {
            std::ifstream file(argv[2]);
            std::string   line;

            while(std::getline(file, line)) {
                std::stringstream   linestream(line);
                std::string         host;
                int                 port;
                int                 conn;

                linestream >> host >> port >> conn;
                std::cout << "Conn\t" << host << "\t" << port << "\t" << conn << "\n";
                for (int i = 0 ; i < conn; i++) {
                    sender.push_back(std::thread(libevent, std::ref(send_message_queue), host, port, std::ref(key_holder)));
                }
            }
        }

        {
            listen_port = std::atoi(argv[3]);
            pool_size = std::atoi(argv[4]);
        }
    } else {
        std::cerr << "Ivalid command line parameters" << std::endl;
        std::cerr << "Usage:" << std::endl;
        std::cerr << "app [private key file] [config file] [listen port] [pool limit]" << std::endl;

        exit(1);
    }

    Counters counters;
    std::thread trd([&counters, &send_message_queue, &key_holder](){
        mh::libevent::LibEvent levent;
        char printbuf[100000];
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::string ip = getMyIp();
            std::string host = getHostName();

            uint64_t timestamp = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now()).time_since_epoch().count();
            memset(printbuf, 0, 100000);
            snprintf(
                        printbuf,
                        100000,
                        "{\"params\": \n"
                        "   {\"network\":\"net-dev\", \"group\": \"proxy\", \"server\": \"%s\", \"timestamp_ms\": %ld,\n"
                        "   \"metrics\": [\n"
                        "        {\"metric\": \"qps\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"qps_trash\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"qps_no_req\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"qps_inv\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"qps_inv_sign\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"qps_success\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"queue\", \"type\": \"sum\", \"value\": %ld},\n"
                        "        {\"metric\": \"ip\", \"type\": \"none\", \"value\": \"%s\"},\n"
                        "        {\"metric\": \"mh_addr\", \"type\": \"none\", \"value\": \"%s\"},\n"
                        "        {\"metric\": \"version\", \"type\": \"none\", \"value\": \"%d.%d\"}\n"
                        "    ]},\n"
                        "\"id\": 1}",
                        host.c_str(), timestamp,
                        counters.qps.load(),
                        counters.qps_trash.load(),
                        counters.qps_no_req.load(),
                        counters.qps_inv.load(),
                        counters.qps_inv_sign.load(),
                        counters.qps_success.load(),
                        send_message_queue.size_approx(),
                        ip.c_str(),
                        key_holder.Text_addres.c_str(),
                        VESION_MAJOR,
                        VESION_MINOR
                        );

            std::string req_post(printbuf);
            std::string response;
            levent.post_keep_alive("172.104.236.166", 5797, "172.104.236.166", "/save-metrics", req_post, response);

            counters.qps.store(0);
            counters.qps_trash.store(0);
            counters.qps_no_req.store(0);
            counters.qps_inv.store(0);
            counters.qps_inv_sign.store(0);
            counters.qps_success.store(0);
        }
    });

    PROXY_SERVER PS(listen_port, send_message_queue, pool_size, counters);
    PS.start();

    return 0;
}
