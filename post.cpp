#include  "post.hpp"
#include <fstream>

PostData::PostData(): config_json("/etc/filetrace/filetrace.json"), 
                       url("http://localhost:8080/api/events"),
                       content_type("Content-Type: application/json")
{
    curl_global_init(CURL_GLOBAL_ALL); 
    curl = curl_easy_init(); 
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); 
        curl_easy_setopt(curl, CURLOPT_POST, 1L); 
        headers = curl_slist_append(headers, content_type.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    }else {
        std::cerr << "Failed to initialize CURL!" << std::endl;
        throw std::runtime_error("CURL initialization failed");
    }
    return;
}

PostData::~PostData()
{
    curl_slist_free_all(headers); 
    curl_easy_cleanup(curl); 
    return;
}

size_t PostData::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

size_t PostData::load_config(const std::string& configFile) {
    std::ifstream file(configFile);
    if (!file.is_open()) {
        std::cerr << "Could not open config file: " << configFile << std::endl;
        return -1; 
    }
    try {
        file >> config_json_obj;
        file.close();
        url = config_json_obj["url"].get<std::string>();
        skip_processes = config_json_obj["skip_processes_list"].get<std::vector<std::string>>();
        conf_list = config_json_obj["config_list"].get<std::vector<std::string>>();
        std::cout << "Configuration loaded successfully from " << configFile << std::endl;
        return 0;
    } catch (json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    } catch (json::type_error& e) {
        std::cerr << "JSON type error: " << e.what() << std::endl;
    } catch (std::exception& e) {
        std::cerr << "General error: " << e.what() << std::endl;
    }
    return -1; 
}

size_t PostData::send(struct event &e)
{
    std::string data = convert_to_string(e);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
    } else {
        std::cout << "HTTP POST successful!" << std::endl;
        std::cout << "Response: " << readBuffer << std::endl;
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        std::cout << "HTTP Status Code: " << http_code << std::endl;
    }
    return 0; 
}

std::string PostData::convert_to_string(struct event &e)
{
    json json_data;
    int flag = e.flag;
    json_data["pid"] = e.pid;
    json_data["ppid"] = e.ppid;
    json_data["cmd"] = e.cmd;
    json_data["pcmd"] = e.pcmd;
    json_data["i_ino"] = e.i_ino;
    json_data["filename"] = e.filename;
    json_data["oldfilename"] = e.oldfilename;
    json_data["username"] = get_username_by_uid(e.uid);
    json_data["groupname"] = get_groupname_by_gid(e.gid);
    return json_data.dump(); 
}

bool PostData::is_valid_event(struct event &e)
{
    if (e.pid == 0 || e.ppid == 0) {
        return false; 
    }
    if (std::find(skip_processes.begin(), skip_processes.end(), e.cmd) != skip_processes.end()) {
        return false; 
    }
    if (e.filename[0] == '\0' || e.dir1[0] == '\0') {
        return false; 
    }
    if(std::find(conf_list.begin(), conf_list.end(), e.cmd) == conf_list.end()) {
        return false; 
    }
    return true; 
}
std::string PostData::get_username_by_uid(unsigned int uid)
{
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        return std::string(pw->pw_name);
    }
    return std::to_string(uid); 
}
std::string PostData::get_groupname_by_gid(unsigned int gid)
{
    struct group *gr = getgrgid(gid);
    if (gr) {
        return std::string(gr->gr_name);
    }
    return std::to_string(gid); 
}