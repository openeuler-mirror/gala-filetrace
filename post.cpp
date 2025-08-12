#include  "post.hpp"

PostData::PostData()
{
    this->content_type = "Content-Type: application/json";
    curl_global_init(CURL_GLOBAL_ALL); 
    curl = curl_easy_init(); 
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); 
        curl_easy_setopt(curl, CURLOPT_POST, 1L); 
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, content_type.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
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
size_t PostData::load_config(const std::string& configFile) {
}