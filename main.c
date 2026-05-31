#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>


int main(){
    
    int listenfd, connfd;
    struct sockaddr_in servaddr;

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr = INADDR_ANY;
    servaddr.sin_port = htons(1920);

    socket(AF_INET, SOCK_RAW)

}