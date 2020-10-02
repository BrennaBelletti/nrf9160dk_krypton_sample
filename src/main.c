/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <net/socket.h>
#include <modem/bsdlib.h>
#include <net/tls_credentials.h>
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_key_mgmt.h>
#include <net/aws_iot.h>
#include <cJSON.h>

#define HTTPS_PORT 8036

#define HTTP_HEAD                                                              \
	"POST /v1/provisioning/aws/iot/bootstrap HTTP/1.1\r\n"                      \
	"Host: krypton.soracom.io:8036\r\n"                                         \
	"Content-Length: 47\r\n"													\
	"Content-Type: application/json\r\n\r\n"									 \
	"{\"requestParameters\":{\"skipCertificates\":true}}"

#define HTTP_HEAD_LEN (sizeof(HTTP_HEAD) - 1)

#define CERT_HEAD_BEGIN "POST /v1/provisioning/aws/iot/certificates/"

#define CERT_HEAD_END																	\
	" HTTP/1.1\r\n"                      										\
	"Host: krypton.soracom.io:8036\r\n"                                         		\
	"Content-Type: application/json\r\n\r\n"

#define ROOT_CA_HTTP_HEAD                                                              \
	"POST /v1/provisioning/aws/iot/ca_certificate HTTP/1.1\r\n"                      \
	"Host: krypton.soracom.io:8036\r\n"                                         \
	"Content-Type: application/json\r\n\r\n"

#define ROOT_CA_HTTP_HEAD_LEN (sizeof(ROOT_CA_HTTP_HEAD) - 1)

#define HTTP_HDR_END "\r\n\r\n"

#define RECV_BUF_SIZE 4096
#define TLS_SEC_TAG 42

static const char send_buf[] = HTTP_HEAD;
static const char root_ca_send_buf[] = ROOT_CA_HTTP_HEAD;
static char recv_buf[RECV_BUF_SIZE];
static char cert_recv_buf[RECV_BUF_SIZE];
static char root_ca_recv_buf[RECV_BUF_SIZE];

/* Certificate for `krypton.soracom.io` */
static const char cert[] = {
	#include "../cert/GlobalSign-Root-CA-R2"
};

BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");


/* Initialize AT communications */
int at_comms_init(void)
{
	int err;

	err = at_cmd_init();
	if (err) {
		printk("Failed to initialize AT commands, err %d\n", err);
		return err;
	}

	err = at_notif_init();
	if (err) {
		printk("Failed to initialize AT notifications, err %d\n", err);
		return err;
	}

	return 0;
}

/* Provision certificate to modem */
int cert_provision(void)
{
	int err;
	bool exists;
	u8_t unused;

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    &exists, &unused);
	if (err) {
		printk("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		/* For the sake of simplicity we delete what is provisioned
		 * with our security tag and reprovision our certificate.
		 */
		err = modem_key_mgmt_delete(TLS_SEC_TAG,
					    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			printk("Failed to delete existing certificate, err %d\n",
			       err);
		}
	}

	printk("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				   cert, sizeof(cert) - 1);
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		return err;
	}

	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};

	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	return 0;
}


void main(void)
{
	int err;
	int fd;
	char *p;
	int bytes;
	size_t off;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	printk("HTTPS client sample started\n\r");

	err = bsdlib_init();
	if (err) {
		printk("Failed to initialize bsdlib!");
		return;
	}

	/* Initialize AT comms in order to provision the certificate */
	err = at_comms_init();
	if (err) {
		return;
	}

	/* Provision certificates before connecting to the LTE network */
	//err = cert_provision();
	if (err) {
		return;
	}

	printk("Waiting for network.. ");
	err = lte_lc_init_and_connect();
	if (err) {
		printk("Failed to connect to the LTE network, err %d\n", err);
		return;
	}
	printk("OK\n");

	err = getaddrinfo("krypton.soracom.io", NULL, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return;
	}

	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd == -1) {
		printk("Failed to open socket!\n");
		goto clean_up;
	}

	/* Setup TLS socket options */
	err = tls_setup(fd);
	if (err) {
		goto clean_up;
	}

	printk("Connecting to %s\n", "krypton.soracom.io");
	err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

	off = 0;
	do {
		bytes = send(fd, &send_buf[off], HTTP_HEAD_LEN - off, 0);
		if (bytes < 0) {
			printk("send() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (off < HTTP_HEAD_LEN);

	printk("Sent %d bytes\n", off);

	off = 0;
	do {
		bytes = recv(fd, &recv_buf[off], RECV_BUF_SIZE - off, 0);
		//printk("bytes: %d\n", bytes);
		if (bytes < 0) {
			printk("recv() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

	printk("Received %d bytes\n", off);

	/* Print HTTP response */
	p = strstr(recv_buf, "\r\n\r\n");
	if (p) {
		recv_buf[off + 1] = '\0';
		off = p - recv_buf;
		//printk("\n>\t %s\n\n", recv_buf);
		//printk("\n>\t %s\n\n", recv_buf + off);
	}

	/* Parse Krypton Response JSON */
	char *responsebody = recv_buf + off;
	const cJSON *privateKey = NULL;

	cJSON *json = cJSON_Parse(responsebody);
	privateKey = cJSON_GetObjectItemCaseSensitive(json, "privateKey");

	if (cJSON_IsString(privateKey) && (privateKey->valuestring != NULL))
    {
        //printk("Successfully parsed JSON! \"%s\"\n", privateKey->valuestring);

		/* Store private key */
		printk("Provisioning private key\n");

		/*  Provision certificate to the modem */
		err = modem_key_mgmt_write(CONFIG_AWS_IOT_SEC_TAG,
					MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT,
					privateKey->valuestring, sizeof(privateKey->valuestring) - 1);
		if (err) {
			printk("Failed to provision certificate, err %d\n", err);
			goto clean_up;
		}
    }


	/* Use cert key from Krypton request to download cert */ 

	printk("Requesting certificate\n");
	const cJSON *certId = cJSON_GetObjectItemCaseSensitive(json, "certificateId");

	char http_request[200];

	strcpy(http_request, CERT_HEAD_BEGIN);
	strcat(http_request, certId->valuestring);
	strcat(http_request, CERT_HEAD_END);

	size_t cert_head_length = (sizeof(http_request)-1);

	printk("Request is: %s\n", http_request);

	err = getaddrinfo("krypton.soracom.io", NULL, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return;
	}

	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd == -1) {
		printk("Failed to open socket!\n");
		goto clean_up;
	}

	/* Setup TLS socket options */
	err = tls_setup(fd);
	if (err) {
		goto clean_up;
	}

	printk("Connecting to %s\n", "krypton.soracom.io");
	err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

	off = 0;
	do {
		bytes = send(fd, &http_request[off], cert_head_length - off, 0);
		if (bytes < 0) {
			printk("send() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (off < cert_head_length);

	printk("Sent %d bytes\n", off);

	off = 0;
	do {
		bytes = recv(fd, &cert_recv_buf[off], RECV_BUF_SIZE - off, 0);
		//printk("bytes: %d\n", bytes);
		if (bytes < 0) {
			printk("recv() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

	printk("Received %d bytes\n", off);

	/* Print HTTP response */
	//p = strstr(cert_recv_buf, "\r\n\r\n");
	//printk("\n>\t %s\n\n", p);

	/* Store cert */
	printk("Provisioning public certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(CONFIG_AWS_IOT_SEC_TAG,
				MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT,
				p, sizeof(p) - 1);
	if (err) {
		printk("Failed to provision public certificate, err %d\n", err);
		goto clean_up;
	}

	/* Request AWS Root CA Cert */ 
	err = getaddrinfo("krypton.soracom.io", NULL, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return;
	}

	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd == -1) {
		printk("Failed to open socket!\n");
		goto clean_up;
	}

	/* Setup TLS socket options */
	err = tls_setup(fd);
	if (err) {
		goto clean_up;
	}

	printk("Connecting to %s\n", "krypton.soracom.io");
	err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

	off = 0;
	do {
		bytes = send(fd, &root_ca_send_buf[off], ROOT_CA_HTTP_HEAD_LEN - off, 0);
		if (bytes < 0) {
			printk("send() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (off < ROOT_CA_HTTP_HEAD_LEN);

	printk("Sent %d bytes\n", off);

	off = 0;
	do {
		bytes = recv(fd, &root_ca_recv_buf[off], RECV_BUF_SIZE - off, 0);
		//printk("bytes: %d\n", bytes);
		if (bytes < 0) {
			printk("recv() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

	printk("Received %d bytes\n", off);

	/* Print HTTP response */
	p = strstr(root_ca_recv_buf, "\r\n\r\n");
	//printk("\n>\t %s\n\n", p);

	/* Store cert */ 
	printk("Provisioning root CA certificate to the modem\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(CONFIG_AWS_IOT_SEC_TAG,
				MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				p, sizeof(p) - 1);
	if (err) {
		printk("Failed to provision root CA certificate, err %d\n", err);
		goto clean_up;
	}

	struct aws_iot_config config = {
		.socket = 8883
	};

	/* Use stored certs to make AWS IoT Request */ 
	err = aws_iot_init(&config, NULL);
	if (err) {
		printk("AWS IoT library could not be initialized, error: %d\n",
		       err);
		goto clean_up;
	}

	err = aws_iot_connect(&config);
	if (err) {
		printk("aws_iot_connect failed: %d\n", err);
		goto clean_up;
	}

	char *message = "Hello World!";

	

	printk("Finished, closing socket.\n");

clean_up:
	freeaddrinfo(res);
	(void)close(fd);
}
