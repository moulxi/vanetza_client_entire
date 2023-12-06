// for app
#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <string>
#include <cstring>
#include <fstream>
#include <vector>
#include <sys/stat.h>// to check if file exist or not

// for socket
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define BUF_SIZE (102400)

using namespace std;

inline void sendFile(int sockfd1, string filePath, int bufferSize)
{
    ifstream fileFd(filePath, std::ios::binary);
    vector<char> sendFileBuffer(std::istreambuf_iterator<char>(fileFd), {});
    send(sockfd1, sendFileBuffer.data(), bufferSize, 0);
    fileFd.close();
}

inline void receiveFile(int sockfd1, string filePath, int bufferSize)
{
    vector<char> receiveFileBuffer(BUF_SIZE);
    ofstream fileFd(filePath, std::ios::binary);
    ssize_t fileSize = recv(sockfd1, receiveFileBuffer.data(), BUF_SIZE, 0);
    fileFd.write(receiveFileBuffer.data(), fileSize);
    fileFd.close();
}

int removeIfExist(string path)
{
    struct stat statBuffer;
    if(stat(path.c_str(),&statBuffer) == 0)
    {
        string theCommand = "rm " + path;
        system(theCommand.c_str());
        return 0;
    }
    else
    {
        return 1;
    }
}

int main(int argc, char *argv[])
{
    //setup
    int port = 10000;
    char *ip = "140.118.155.146";


    if(strcmp(argv[1], "reset") == 0)
    {
        removeIfExist("../test/ACA/aa.key");
        removeIfExist("../test/ACA/aa.pub");
        removeIfExist("../test/Cache/aa.cert");
        system("bin/certify generate-key ../test/ACA/aa.key");
        system("bin/certify extract-public-key --private-key ../test/ACA/aa.key ../test/ACA/aa.pub");
    }
    else if(strcmp(argv[1], "certRequest") == 0 || strcmp(argv[1], "certValidate") == 0)
    {
        //socket
        int sockfd1 = socket(AF_INET, SOCK_STREAM, 0);


        //set sockaddr_in
        struct sockaddr_in clientAddr;
        bzero(&clientAddr, sizeof(clientAddr));
        clientAddr.sin_family = AF_INET;
        clientAddr.sin_port = htons(port);//set port
        inet_aton(ip, (struct in_addr *) &clientAddr.sin_addr.s_addr);//set remote ip


        //connect
        if(connect(sockfd1, (struct sockaddr *) &clientAddr, sizeof(clientAddr)) == -1)
        {
            cout << "connect error" << endl;
        }

        //send message
        char sebuf[BUF_SIZE];
        memset(sebuf, 0, BUF_SIZE);
        char rebuf[BUF_SIZE];
        memset(rebuf, 0, BUF_SIZE);


        if(strcmp(argv[1], "certRequest") == 0)
        {
            // if the old file exist, remove it
            removeIfExist("../test/Cache/aa.cert");

            string requestType = "CERT_REQUEST";
            send(sockfd1, requestType.c_str(), requestType.size(), 0);

            memset(rebuf, 0, BUF_SIZE);
            recv(sockfd1, rebuf, BUF_SIZE, 0);
            if(strcmp(rebuf, "CERT_REQUEST_READY") == 0)
            {
                cout << "received ready" << endl;
                sleep(3);
                system("bin/certify client --action request --file_path ../test/ACA/aa.pub --address 140.118.155.146 --port 20002");
            }
        }
        else if(strcmp(argv[1], "certValidate") == 0)
        {
            string requestType = "CERT_VALIDATE";
            send(sockfd1, requestType.c_str(), requestType.size(), 0);
            cout << "send validate request" << endl;

            memset(rebuf, 0, BUF_SIZE);
            recv(sockfd1, rebuf, BUF_SIZE, 0);
            if(strcmp(rebuf, "CERT_VALIDATE_READY") == 0)
            {
                cout << "call the command" << endl;
                sleep(3);
                system("bin/certify client --action verify --file_path ../test/Cache/aa.cert --address 140.118.155.146 --port 20003");
            }
        }
        close(sockfd1);
    }
}