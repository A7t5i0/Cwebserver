#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <errno.h>

#define PORT 5000

#define BUF_SIZE 8000000
#define REQ_SIZE 2048
#define FILENAME_SIZE 1024
#define MAX_LINE 2048

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("unable to create ssl context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "privateKey.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

char *content_header(char *start, size_t startlen) {
    char *content_type = "Content-Type: text/html; charset=UTF-8\n";
    size_t q = 0;
    size_t w = 0;
    size_t e = 0;
    size_t r = 0;
    size_t t = 0;
    size_t y = 0;
    size_t u = 0;
    size_t ii = 0;
    size_t o = 0;
    size_t p = 0;
    size_t a = 0;
    size_t s = 0;
    size_t mp = 0;
    size_t mo = 0;
    size_t dc = 0;
    size_t hk1c = 0;
    size_t hk2c = 0;
    size_t hk3c = 0;
    size_t hk4c = 0;
    size_t hk5c = 0;
    size_t hk6c = 0;
    char *gif = ".gif";
    char *txt = ".txt";
    char *jpg = ".jpg";
    char *jpeg = ".jpe";
    char *js = ".js";
    char *png = ".png";
    char *ico = ".ico";
    char *zip = ".zip";
    char *php = ".php";
    char *tar = ".tar";
    char *rar = ".rar";
    char *pdf = ".pdf";
    char *mp4 = ".mp4";
    char *mov = ".mov";
    char *dot_c = ".c";
    char *hk1 = "./";
    char *hk2 = "sudo";
    char hk3 = '"';
    char *hk4 = ".exe";
    char *hk5 = "'";
    char *hk6 = "cat";
    for (size_t i = 0; i < startlen; i++) {
        if (strlen(start) != 1) {
            if (start[i] == gif[q]) {
                q++;
                if (q == strlen(gif)) {
                    content_type = "Content-Type: image/gif; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == txt[w]) {
                w++;
                if (w == strlen(txt)) {
                    content_type = "Content-Type: text/plain; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == jpg[e]) {
                e++;
                if (e == strlen(jpg)) {
                    content_type = "Content-Type: image/jpg; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == jpeg[r]) {
                r++;
                if (r == strlen(jpeg)) {
                    content_type = "Content-Type: image/jpeg; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == js[t]) {
                t++;
                if (t == strlen(js)) {
                    content_type = "Content-Type: application/javascript; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == png[y]) {
                y++;
                if (y == strlen(png)) {
                    content_type = "Content-Type: image/png; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == ico[u]) {
                u++;
                if (u == strlen(ico)) {
                    content_type = "Content-Type: image/ico; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == zip[ii]) {
                ii++;
                if (ii == strlen(zip)) {
                    content_type = "Content-Type: application/octet-stream; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == php[o]) {
                o++;
                if (o == strlen(php)) {
                    content_type = "Content-Type: text/html; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == tar[p]) {
                p++;
                if (p == strlen(tar)) {
                    content_type = "Content-Type: image/tar; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == rar[a]) {
                a++;
                if (a == strlen(rar)) {
                    content_type = "Content-Type: application/octet-stream; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == pdf[s]) {
                s++;
                if (s == strlen(pdf)) {
                    content_type = "Content-Type: application/pdf; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == mp4[mp]) {
                mp++;
                if (mp == strlen(mp4)) {
                    content_type = "Content-Type: video/mp4; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == mov[mo]) {
                mo++;
                if (mo == strlen(mov)) {
                    content_type = "Content-Type: video/quicktime; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == dot_c[dc]) {
                dc++;
                if (dc == strlen(dot_c)) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == hk1[hk1c]) {
                hk1c++;
                if (hk1c == strlen(hk1)) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == hk2[hk2c]) {
                hk2c++;
                if (hk2c == strlen(hk2)) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == hk3) {
                hk3c++;
                if (hk3c == 1) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == hk4[hk4c]) {
                hk4c++;
                if (hk4c == strlen(hk4)) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == hk5[hk5c]) {
                hk5c++;
                if (hk5c == strlen(hk5)) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            } if (start[i] == hk6[hk6c]) {
                hk6c++;
                if (hk6c == strlen(hk6)) {
                    content_type = "Content-Type: forbidden; charset=UTF-8\n";
                    return content_type;
                }
            }
        }
    }
    return content_type;
}

char *url_to_file(char *filename) {
    size_t fnsize = 0;
    size_t fnlen[2];
    char *fnlist[2];
    fnlist[0] = filename;
    fnlist[1] = ".html";
    for (int i = 0; i < 2; i++) {
        fnlen[i] = strlen(fnlist[i]);
        fnsize += fnlen[i];
    }
    char *filename2 = malloc((fnsize + 1) * sizeof(filename2));
    if (filename2 == NULL) {
        perror("malloc filename2 failed");
        exit(1);
    }
    filename2[fnsize] = '\0';
    fnsize = 0;
    for (int i = 0; i < 2; i++) {
        memmove(filename2 + fnsize, fnlist[i], fnlen[i]);
        fnsize += fnlen[i];
    }

    return filename2;
}

void write_file(char *buf, char *filename, SSL *ssl) {
    if (access(filename, F_OK) != -1) {
        printf("\nfile is found\n");
        int fd = open(filename, O_RDONLY);
        ssize_t bytes_read;
        while(bytes_read = read(fd, buf, sysconf(_SC_PAGESIZE))) {
            SSL_write(ssl, buf, bytes_read);
        }
        printf("file written\n");
        free(ssl);
        close(fd);
    } else {
        printf("\nfile NOT found\n");
    }
}

void upload_file(SSL *ssl) {
    ssize_t bytes_read = 0;
    ssize_t bytes_written = 0;
    char buf[256];
    
    ssize_t first_read = SSL_read(ssl, buf, sizeof buf);
    // buf[first_read-1] = '\0';
    char *test = strstr(buf, "\n\n");
    if (test == NULL) {
        perror("weird request bro\n");
    }
    char *test2 = strstr(buf, "\r\n\r\n");
    if (test2 == NULL) {
        perror("weird request bro\n");
    }
    printf("test1:\n%s\ntest2:\n%s\n", test, test2);
    char *postheader = strstr(buf, "Content-Disposition: ");
    char *ph2 = malloc(sizeof(char)*100);
    memcpy(ph2, postheader, 100);

    char *ph3 = strstr(ph2, "filename=");
    ph3 += 10;
    char *removechar = strchr(ph3, '"');
    *removechar = '\0';

    printf("strlen(filename):\n%ld\n", strlen(ph3));
    char *contentType = content_header(ph3, strlen(ph3));
    printf("ph3 content type:\n%s\n", contentType);

    if (access(ph3, F_OK) != -1) {
        printf("name in use\n");
    } else {
        if (contentType != "Content-Type: forbidden; charset=UTF-8\n") {
            ssize_t offset = test2 - buf;
            offset += 4;
            char *dataptr = buf + offset;
            
            ssize_t not_first_read = first_read - offset;
            
            printf("data:\n%s\n", dataptr);
            FILE* tmp = fopen(ph3, "wb");
            fwrite(dataptr, not_first_read, 1, tmp);
            while((bytes_read = SSL_read(ssl, dataptr, sizeof buf))){      
                printf("bytesread: %ld\n", bytes_read);
                bytes_written = fwrite(dataptr, bytes_read, 1, tmp);
                if (bytes_read == bytes_written) {
                    printf("read==write\n");
                } else if (bytes_read > bytes_written) {
                    printf("read>write\n");
                }
                if (bytes_read < first_read) {
                    break;
                }
            }
            fclose(tmp);
        }
    }
    printf("\nupload successful\n");
    SSL_free(ssl);
    free(ph2);
}

char *content_length_header(char *filename) {
    FILE *f = fopen(filename, "rb");
    fseek(f, 0L, SEEK_END);
    size_t filesize = ftell(f);
    char *content_length = malloc(sizeof("Content-Length: %lu\nConnection: close\n\n" + 10));
    sprintf(content_length, "Content-Length: %lu\nConnection: close\n\n", filesize);
    fclose(f);
    return content_length;
}

int main() {
    sigset_t set; //add set of signals
    sigemptyset(&set); //null it out so its empty
    sigaddset(&set, SIGPIPE); //add signal to sigpipe
    sigprocmask(SIG_BLOCK, &set, NULL); //call function to block signals on that set

    char buf[BUF_SIZE];
    
    int server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("failed to create socket");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in6 addr6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(PORT),
        .sin6_flowinfo = 0,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_scope_id = 0};
    socklen_t addr_len = sizeof(struct sockaddr_in6);

    if (bind(server_fd, (struct sockaddr *)&addr6, sizeof(addr6))) {
        perror("failed to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("failed to listen");
        exit(EXIT_FAILURE);
    }

    int new_socket;
    SSL_CTX *ctx;
    ctx = create_context();
    configure_context(ctx);
    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&addr6, (socklen_t*)&addr_len))<0) {
            perror("failed to accept connction");
            exit(EXIT_FAILURE);
        }

        //forking
        int child = fork();
        if (child) {
            continue;
        }

        SSL *ssl;
        size_t headersize = '\0';
        headersize += strlen("HTTP/1.1 200 OK\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\nConnection: Closed\n\n");
        char headers[headersize];
        strcat(headers, "HTTP/1.1 200 OK\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\nConnection: Closed\n\n");
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }

        char req[2048];
        SSL_read(ssl, req, 2048);
        printf("req: %s\n", req);
        char *start;
        // printf("req: %s\n", req);
        start = strstr(req, " HTTP/");
        // printf("start: %s\n", start);
        if (strncmp(req, "GET ", 4) == 0) {
            start = req + 4;
            char *end = start;
            while (*end != ' ' && *end != '\0') {
                end++;
            }
            char *remove;
            remove = strstr(start, " HTTP/1.1");
            if (remove != 0) {
                *remove = '\0';
            }
            //continue here
            size_t startlen = strlen(start);
            char *content_type = content_header(start, startlen);
            char *homepage = "index.html";
            char *filename = start + 1;
            char *filename2 = url_to_file(filename);
            char *page404 = "404.html";

            size_t headersize = '\0';
            headersize += strlen("HTTP/1.1 200 OK\nDate: ");
            headersize += strlen(__DATE__);
            headersize += strlen(" GMT\nServer: GNU/linux\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\n");
            headersize += strlen(content_type);

            if (start[0] = '/' && startlen < 2) {
                printf("homepage\n");
                char *content_length = content_length_header(homepage);
                headersize += strlen(content_length);
                char headers[headersize];
                strcat(headers, "HTTP/1.1 200 OK\nDate: ");
                strcat(headers, __DATE__);
                strcat(headers, " GMT\nServer: GNU/linux\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\n");
                strcat(headers, content_type);
                strcat(headers, content_length);
                printf("headers: %s\n", headers);
                SSL_write(ssl, headers, headersize);
                write_file(buf, homepage, ssl);
                free(content_length);
            } else if (access(filename, F_OK) != -1 && content_type != "Content-Type: forbidden\n") {
                printf("filename: %s\n", filename);
                char *content_length = content_length_header(filename);
                headersize += strlen(content_length);
                char headers[headersize];
                strcat(headers, "HTTP/1.1 200 OK\nDate: ");
                strcat(headers, __DATE__);
                strcat(headers, " GMT\nServer: GNU/linux\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\n");
                strcat(headers, content_type);
                strcat(headers, content_length);
                printf("headers: %s\n", headers);
                SSL_write(ssl, headers, headersize);
                write_file(buf, filename, ssl);
                free(content_length);
            } else if (access(filename2, F_OK) != -1 && content_type != "Content-Type: forbidden\n") {
                printf("filename2: %s\n", filename2);
                char *content_length = content_length_header(filename2);
                headersize += strlen(content_length);
                char headers[headersize];
                strcat(headers, "HTTP/1.1 200 OK\nDate: ");
                strcat(headers, __DATE__);
                strcat(headers, " GMT\nServer: GNU/linux\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\n");
                strcat(headers, content_type);
                strcat(headers, content_length);
                printf("headers: %s\n", headers);
                SSL_write(ssl, headers, headersize);
                write_file(buf, filename2, ssl);
                free(content_length);
            } else {
                printf("404\n");
                char *content_length = content_length_header(page404);
                headersize += strlen(content_length);
                char headers[headersize];
                strcat(headers, "HTTP/1.1 200 OK\nDate: ");
                strcat(headers, __DATE__);
                strcat(headers, " GMT\nServer: GNU/linux\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\n");
                strcat(headers, content_type);
                strcat(headers, content_length);
                printf("headers: %s\n", headers);
                SSL_write(ssl, headers, headersize);
                write_file(buf, page404, ssl);
                free(content_length);
            }

        } else if (strncmp(req, "POST ", 5) == 0) {
            printf("POST method is being used\n");
            if (start[0] = '/') {
                upload_file(ssl);
            }
            
        } else {
            printf("request type not yet implemented\n");
            SSL_write(ssl, "request type not yet implemented", strlen("request type not yet implemented"));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        shutdown(new_socket, SHUT_RDWR);
        close(new_socket);
        exit(0); 
    }
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}