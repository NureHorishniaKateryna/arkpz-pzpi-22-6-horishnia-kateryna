#include <iostream>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "mqtt/async_client.h"

const std::string API_HOST = "http://127.0.0.1:9090/api";
const std::string AUTH_TOKEN = getenv("AUTH_TOKEN");
const std::string MQTT_SERVER_ADDRESS = getenv("MQTT_ADDRESS");
const std::string MQTT_USER = getenv("MQTT_USER");
const std::string MQTT_PASS = getenv("MQTT_PASS");
constexpr time_t TRIGGER_TIMEOUT = 10;

bool schedule[24] = {false};

std::atomic<bool> triggered(false);
std::atomic<bool> manual_state(false);
std::condition_variable cv;
std::mutex cv_mutex;

std::atomic<bool> current_state(false);

size_t curl_write_to_string_callback(char* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string curlRequest(const std::string& endpoint) {
    std::string response;

    CURL* curl = curl_easy_init();
    if (!curl)
        return "";

    curl_slist* headers = curl_slist_append(nullptr, ("token: " + AUTH_TOKEN).c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_URL, (API_HOST + endpoint).c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_string_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return response;
}

void resetSchedule() {
    for(int32_t i = 0; i <= 24; i++) {
        schedule[i] = false;
    }
}

void fetchSchedule() {
    std::string sched_str = curlRequest("/device/schedule");
    nlohmann::json sched;

    try {
        sched = nlohmann::json::parse(sched_str);
        std::cout << "Schedule fetched from server" << std::endl;
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "Failed to parse schedule: " << e.what() << std::endl;
    }

    resetSchedule();

    for(auto sched_item : sched) {
        int32_t start_hour;
        int32_t end_hour;

        try {
            start_hour = sched_item["start_hour"].get<int32_t>();
            end_hour = sched_item["end_hour"].get<int32_t>();
        } catch (const nlohmann::json::type_error& e) {
            continue;
        }

        if(start_hour < 0 || start_hour > 23 || end_hour < 0 || end_hour > 23 || start_hour > end_hour) {
            continue;
        }

        for(int32_t i = start_hour; i <= end_hour; i++) {
            schedule[i] = true;
        }
    }
}

void deviceLoop() {
    int64_t trigger_expires_at = 0;

    while(true) {
        bool enabled = false;

        if(triggered.load()) {
            enabled = true;
            trigger_expires_at = time(nullptr) + TRIGGER_TIMEOUT;
            triggered.store(false);
        }
        if(time(nullptr) <= trigger_expires_at) {
            enabled = true;
        } else {
            enabled = manual_state.load();
        }

        std::time_t t = std::time(nullptr);
        const std::tm* now = std::localtime(&t);
        enabled = enabled || schedule[now->tm_hour];

        if(current_state != enabled) {
            std::cout << "New state: " << enabled << std::endl;
            current_state.store(enabled);
            cv.notify_all();
        }
    }
}

void mqttHandler() {
    mqtt::async_client client(MQTT_SERVER_ADDRESS, "client_id");
    mqtt::connect_options connOpts;
    connOpts.set_user_name(MQTT_USER);
    connOpts.set_password(MQTT_PASS);
    connOpts.set_automatic_reconnect(true);
    connOpts.set_ssl(mqtt::ssl_options_builder().ssl_version(3).finalize());

    client.set_message_callback([](const mqtt::const_message_ptr& msg) {
        if(msg->get_topic().starts_with("config/")) {
            std::cout << "Got config update from server: " << msg->get_payload_str() << std::endl;

            try {
                auto jsonConfig = nlohmann::json::parse(msg->get_payload_str());
                manual_state.store(jsonConfig["enabled_manually"].get<bool>());
            } catch (const nlohmann::json::parse_error& e) {
                std::cerr << "Failed to parse config: " << e.what() << std::endl;
            }
        } else if(msg->get_topic().starts_with("schedule/")) {
            std::cout << "Got schedule update request from server: " << msg->get_payload_str() << std::endl;
            fetchSchedule();
        }
    });

    nlohmann::json state = {
        {"token", AUTH_TOKEN},
        {"enabled", false},
        {"enabled_for", nullptr},
    };

    bool last_enabled = false;
    int64_t enabled_at = 0;

    try {
        client.connect(connOpts)->wait();
        client.subscribe("config/"+AUTH_TOKEN, 1);
        client.subscribe("schedule/"+AUTH_TOKEN, 1);
        std::cout << "Connected to MQTT server." << std::endl;

        while (true) {
            std::unique_lock<std::mutex> lock(cv_mutex);
            bool enabled = cv.wait_for(lock, std::chrono::seconds(1), [] { return current_state.load(); });
            if (enabled) {
                if(enabled != last_enabled)
                    enabled_at = time(nullptr);
                state["enabled"] = true;
                state["enabled_for"] = nullptr;
            } else {
                state["enabled"] = false;
                if(enabled_at > 0)
                    state["enabled_for"] = time(nullptr) - enabled_at;
                else
                    state["enabled_for"] = nullptr;
            }

            if(enabled != last_enabled) {
                std::cout << "Sent: enabled = " << enabled << std::endl;
                client.publish("lights-reports", state.dump(), 1, false)->wait();
                last_enabled = enabled;
            }
        }
    } catch (const mqtt::exception& e) {
        std::cerr << "MQTT error: " << e.what() << std::endl;
    }
}

void stdinHandler() {
    std::string input;
    while (std::getline(std::cin, input)) {
        if (input != "trigger")
            continue;

        triggered.store(true);
    }
}

int main() {
    std::cout << "Fetching configuration..." << std::endl;
    std::string config = curlRequest("/device/config");

    try {
        auto jsonConfig = nlohmann::json::parse(config);
        std::cout << "Configuration fetched: " << jsonConfig.dump(4) << std::endl;
        manual_state.store(jsonConfig["enabled_manually"].get<bool>());
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "Failed to parse configuration: " << e.what() << std::endl;
        return 1;
    }

    fetchSchedule();

    std::thread deviceThread(deviceLoop);
    std::thread mqttThread(mqttHandler);
    std::thread stdinThread(stdinHandler);

    deviceThread.join();
    mqttThread.join();
    stdinThread.join();

    return 0;
}
