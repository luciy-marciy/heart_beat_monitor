//
// Created by Dzmitry Valkovich on 8/18/20.
//

#include <magic_enum.hpp>
#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include <iostream>
#include <memory>
#include <random>
#include <string>

#include <crypto.h>
#include <models.h>


int main() {
    std::random_device rd;
    std::mt19937 random_engine{rd()};
    std::uniform_int_distribution status_generator{1, 6};

    bool is_stopped = false;

    nlohmann::json json_answer = nlohmann::json::object();

    Models::Answer answer;

    zmq::context_t context;
    zmq::socket_t socket{context, ZMQ_REP};

    std::cout << "Connecting to heartbeat server..." << std::endl;
    socket.connect("tcp://localhost:12277");

    int status_number;

    std::optional<Models::Status> temp_subsystem;

    Models::Request req_str;
    nlohmann::json j;

    std::string pubkey = "./ec_brainpool_256r1.pub";

    while (true) {
        Crypto::ECC ec;
        int ret;
        ret = ec.LoadPubkey(pubkey.c_str());
        if (ret != 0) {
            std::cerr << "pubkey didn't load " << std::endl;
            return -1;
        }

        zmq::message_t request;
        socket.recv(&request);

        std::string_view request_string = request.to_string_view();
        j = nlohmann::json::parse(request_string);
        Models::from_json(j, req_str);

        ec.SetSignature(req_str.signature);
        ret = ec.Verify((uint8_t *) (req_str.message.c_str()), req_str.message.length(), ec.GetSignature(),
                        ec.GetSignatureLen(), "sha256");
        if (ret != 0) {
            zmq::message_t reply{5};
            memcpy(reply.data(), "error", 5);
            socket.send(reply);

            continue;
        }


        size_t colon_position = req_str.message.find(':');
        if (colon_position == std::string::npos) {
            zmq::message_t reply{5};
            memcpy(reply.data(), "error", 5);
            socket.send(reply);

            continue;
        }
        if (colon_position == 3) {
            is_stopped = true;
        }

        std::string_view timestamp = request_string.substr(colon_position + 1, request_string.size() - 1);

        answer.alive_at = timestamp;

        if (!is_stopped) {
            status_number = status_generator(random_engine);

            temp_subsystem = magic_enum::enum_cast<Models::Status>(status_number);

            if (temp_subsystem.has_value()) {
                answer.subsystems.subsystem1 = temp_subsystem.value();
            }

            status_number = status_generator(random_engine);
            temp_subsystem = magic_enum::enum_cast<Models::Status>(status_number);
            if (temp_subsystem.has_value()) {
                answer.subsystems.subsystem2 = temp_subsystem.value();
            }
        } else {
            answer.subsystems.subsystem1 = Models::Status::OFF;
            answer.subsystems.subsystem2 = Models::Status::OFF;
        }


        Models::to_json(json_answer, answer);
        auto temp_string = json_answer.dump();
        socket.send(zmq::buffer(temp_string), zmq::send_flags::none);
    }

    return 0;
}
