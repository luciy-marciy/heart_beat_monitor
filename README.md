# Heartbeat monitor

## Introduction :

### The purpose is to write a small amount of c++ code compatible with C++ 17 that implements a client server heartbeat monitor.

### Libraries that can be used are :
1. STL (c++17)
1. Boost
1. ZMQ+ZMQCPP (optional for TCP)
1. Pistache (optional for rest), openssl(ecdsa sign)


#### Other requirements : CMake, GCC, Linux
Deliverable :
Github LGPL public repo with the code and the CMakelist.txt
Specification :

1. Client is the c++ process that we need to monitor.
1. Server is the c++ process that we use to monitor the client state.

Features:
1. Every 1 second the server will :
    1. ping the computer of the client to check if the hardware still function
    1. send a “areYouAlive+timestamp” query (TCP) to the port 12277 signed with a private key
    1. the client need to answer on the port 12277 and check that the query is original(thanks to the corresponding pub key) with a JSON (using boost) payload that contains:
        1.	a field with AliveAt<timestamp>
        1.	a structure that contains :
            1. subsystem1: status
            1. subsystem2: status

	        where <status> is a random status taken from an enum field : { OK, OFF, WARNING, ERROR, CRITICAL }
    1. the server should display the server JSON on a webpage (pistache) or in the command line
1. At any time the server can :
    1. send a “stop” instruction with timestamp to the client through another port 12278 signed with the same private key
    1. in this case the client after the usual check will set the status of both subsystems to false


Help openssl:

https://stackoverflow.com/questions/2228860/signing-a-message-using-ecdsa-in-openssl


# Project building
   
   #### Linux and MacOS
       If you are running UNIX based system. 
       Run "prepare.sh" and it will install vcpkg with needed packages.
       
       $ chmod +x prepare.sh
       $ ./prepare.sh
       $ mkdir build
       $ cd build
       $ cmake 
           
#### Build Requirements
- [CMake](https://cmake.org/)
- [VCPKG](https://github.com/microsoft/vcpkg)
