cmake_minimum_required(VERSION 3.15)
project(arkpz-iot)

set(CMAKE_CXX_STANDARD 23)
set(PAHO_WITH_MQTT_C ON)
set(PAHO_BUILD_STATIC ON)

include(FetchContent)
FetchContent_Declare(json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG 9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03)
FetchContent_MakeAvailable(json)
FetchContent_Declare(mqtt
        GIT_REPOSITORY https://github.com/eclipse-paho/paho.mqtt.cpp.git
        GIT_TAG c310578ee68d38cd53e79d7107fb41dc68dbafe0)
FetchContent_MakeAvailable(mqtt)

add_executable(arkpz-iot main.cpp)
target_include_directories(arkpz-iot PRIVATE
        ${mqtt_SOURCE_DIR}/externals/paho-mqtt-c/src
        ${mqtt_SOURCE_DIR}/include
        ${mqtt_BINARY_DIR}
)
target_link_libraries(arkpz-iot
        nlohmann_json::nlohmann_json
        curl
        paho-mqttpp3-static
        paho-mqtt3as-static
)