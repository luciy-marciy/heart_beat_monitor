//
// Created by Dzmitry Valkovich on 8/21/20.
//

#pragma once

#include <nlohmann/json.hpp>

namespace Helper {
    enum class Status {
        OK = 0,
        OFF,
        WARNING,
        ERROR,
        CRITICAL
    };

    struct Subsystems {
        Status subsystem1;
        Status subsystem2;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Subsystems, subsystem1, subsystem2);

    struct Answer {
        std::string alive_at;
        Subsystems subsystems;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Answer, alive_at, subsystems)

    struct Request {
        std::string message;
        std::string signature;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Request, message, signature)
}
