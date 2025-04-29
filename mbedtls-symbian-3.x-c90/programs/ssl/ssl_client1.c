/*
 *  SSL client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "test/certs.h"

#include <string.h>

#define SERVER_PORT 443
//#define SERVER_NAME "api.ipify.org"
//#define SERVER_NAME "m.wikipedia.org"
#define SERVER_NAME "157.240.195.35"
//#define SERVER_NAME "105.73.34.24"
//#define SERVER_NAME "localhost"


#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1


static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

//#define USE_MBEDTLS_NET 1
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#ifdef __GCCE__
void exit(int status){}
#endif
int tcp_send(void *ctx, const unsigned char *buf, size_t len)
{
    int sock_fd = *((int*)ctx);

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;


    ret = (int) send(sock_fd,(const char*)buf, len, 0);
    printf("tcp_send(sock_fd=%d)=%d\n", sock_fd, ret);

    if (ret < 0)
    {
        /*if (net_would_block(ctx) != 0) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }*/

	if (errno == EPIPE) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }

        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}


int tcp_recv(void *ctx, unsigned char *buf, size_t len)
{

    int sock_fd = *((int*)ctx);

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = (int) recv(sock_fd, (char*)buf, len, 0);

    if (ret < 0)
    {

	if (errno == EPIPE) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }

        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;

}



int tcp_connect(const char* host, int port)
{
    int sock_fd = -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
	if(inet_aton(host, &addr.sin_addr) < 1)
	{
		perror("inet_pton");
		return -1;
	}
	printf("inet_pton=0x%08x\n", addr.sin_addr.s_addr);	

    //addr.sin_addr.s_addr = iaddr.s_addr;
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket()");
		return -1;
    }

    if(connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("connect()");
		close(sock_fd);
		return -1;
    }

    printf("tcp_connect(sock_fd=%d)\n", sock_fd);
    return sock_fd;

}

int main(int argc, char** argv)
{
    int ret = 1, len, sock_fd;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 0. Initialize the RNG and the session data
     */


    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        //goto do_exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("  . Loading the CA root certificate ...");
    fflush(stdout);

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        //goto do_exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);
    /*
     * 1. Start the connection
     */
    mbedtls_printf("Connecting to tcp/%s/%d...", SERVER_NAME, SERVER_PORT);
    fflush(stdout);	
	
    if ((sock_fd = tcp_connect("157.240.195.35", SERVER_PORT)) == -1)
	{
        goto do_exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto do_exit;
    }

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto do_exit;
    }

   
    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto do_exit;
    }

    mbedtls_ssl_set_bio(&ssl, &sock_fd, tcp_send, tcp_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto do_exit;
	    break;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf("  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        mbedtls_printf(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
#endif
    } else {
        mbedtls_printf(" ok\n");
    }

    /*
     * 3. Write the GET request
     */
    mbedtls_printf("  > Write to server:");
    fflush(stdout);

    len = sprintf((char *) buf, GET_REQUEST);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto do_exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s", len, (char *) buf);

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf("  < Read from server:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }

        if (ret < 0) {
            mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);
    } while (1);

    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;

do_exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    printf("PRESS ENTER TO EXIT");
    getchar();

    close(sock_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_exit(exit_code);

}

