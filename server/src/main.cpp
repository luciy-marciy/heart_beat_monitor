//
// Created by Dzmitry Valkovich on 8/18/20.
//


#include <zmq.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <iostream>
#include <unistd.h>
#include <chrono>
#include <ctime>

#include <crypto.h>

int main() {

    int ret;

    std::string pkey = "./ec_brainpool_256r1.pkey";

    std::chrono::system_clock::time_point tp, start;
    std::time_t current_time;

    zmq::context_t ctx;
    zmq::socket_t socket{ctx, zmq::socket_type::req};
    socket.bind("tcp://*:12277");

    std::optional<size_t> return_code;
    start = std::chrono::system_clock::now();

    std::string message;
    while (true) {
        Crypto::ECC ec;
        ret = ec.LoadPrivkey(pkey.c_str());
        if (ret != 0) {
            std::cerr << "privkey didn't load" << std::endl;
            return -1;
        }


        tp = std::chrono::system_clock::now();
        current_time = std::chrono::system_clock::to_time_t(tp);
        message = "areYouAlive:" + std::to_string(current_time);


        ret = ec.Sign((uint8_t *) (message.c_str()), message.length(), "sha256");
        if (ret != 0) {
            std::cerr << message << "   failure to sign message" << std::endl;
            return -1;
        }


        nlohmann::json j;
        j["signature"] = ec.DumpSignature();
        j["message"] = message;


        auto t = j.dump();
        std::string_view k = t;
        socket.send(zmq::buffer(k), zmq::send_flags::none);
        std::cout << k << std::endl;

        zmq::message_t answ;
        return_code = socket.recv(answ, zmq::recv_flags::none);
        sleep(1);
    }

    return 0;
}