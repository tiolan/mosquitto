/*
Copyright (c) 2014-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Timo Lange - initial implementation and documentation.
*/

#include "config.h"
#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "http_mosq.h"
#include "util_mosq.h"
#include "send_mosq.h"
#include "net_mosq.h"

#include <errno.h>
#include <string.h>

#define MAX_CONNECT_LEN 256

//TODO: This is essentially the same as mosquitto_socks5_set
int mosquitto_http_set(struct mosquitto *mosq, const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_HTTP
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || strlen(host) > 256) return MOSQ_ERR_INVAL;
	if(port < 1 || port > UINT16_MAX) return MOSQ_ERR_INVAL;

	mosquitto__free(mosq->http_host);
	mosq->http_host = NULL;

	mosq->http_host = mosquitto__strdup(host);
	if(!mosq->http_host){
		return MOSQ_ERR_NOMEM;
	}

	mosq->http_port = (uint16_t)port;

	mosquitto__free(mosq->http_username);
	mosq->http_username = NULL;

	mosquitto__free(mosq->http_password);
	mosq->http_password = NULL;

	if(username){
		if(strlen(username) > UINT8_MAX){
			return MOSQ_ERR_INVAL;
		}
		mosq->http_username = mosquitto__strdup(username);
		if(!mosq->http_username){
			return MOSQ_ERR_NOMEM;
		}

		if(password){
			if(strlen(password) > UINT8_MAX){
				return MOSQ_ERR_INVAL;
			}
			mosq->http_password = mosquitto__strdup(password);
			if(!mosq->http_password){
				mosquitto__free(mosq->http_username);
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	return MOSQ_ERR_SUCCESS;
#else
	UNUSED(mosq);
	UNUSED(host);
	UNUSED(port);
	UNUSED(username);
	UNUSED(password);

	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}

#ifdef WITH_HTTP
int http__send(struct mosquitto *mosq)
{
	struct mosquitto__packet *packet;
	enum mosquitto_client_state state;

	state = mosquitto__get_state(mosq);

	if(state == mosq_cs_http_new){
		packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
		if(!packet) return MOSQ_ERR_NOMEM;

		packet->payload = mosquitto__malloc(sizeof(uint8_t) * MAX_CONNECT_LEN);
		if(!packet->payload)
		{
			mosquitto__free(packet);
			return MOSQ_ERR_NOMEM;
		}

		{ /* Prepare CONNECT package with host and port */
			int length = snprintf(
				(char *)packet->payload + packet->packet_length,
				MAX_CONNECT_LEN - packet->packet_length,
				"CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n", mosq->host, mosq->port, mosq->host, mosq->port);
			if(length < 0)
			{
				mosquitto__free(packet->payload);
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->packet_length += length;
		}

		if (mosq->http_username)
		{ /* base64 encode "username:password", where password potentially is an empty string and append it */
			int length = snprintf(
				(char *)packet->payload + packet->packet_length,
				MAX_CONNECT_LEN - packet->packet_length,
				//TODO: base64 username:password, but base64__encode is only available when building with TLS
				"Proxy-Authorization: basic %s\r\n", "aGVsbG86d29ybGQ=");
			if(length < 0 || length >= MAX_CONNECT_LEN - packet->packet_length)
			{
				mosquitto__free(packet->payload);
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->packet_length += length;
		}

		{ /* Finally append carriage return, newline to terminate the HTTP package */
			int length = snprintf(
				(char *)packet->payload + packet->packet_length,
				MAX_CONNECT_LEN - packet->packet_length,
				"\r\n");
			if(length < 0 || length >= MAX_CONNECT_LEN - packet->packet_length)
			{
				mosquitto__free(packet->payload);
				mosquitto__free(packet);
				return MOSQ_ERR_NOMEM;
			}
			packet->packet_length += length;
		}

		mosquitto__set_state(mosq, mosq_cs_http_start);

		// TODO: How does this work with unknown size?
		mosq->in_packet.pos = 0;
		mosq->in_packet.packet_length = 70;
		mosq->in_packet.to_process = 70;
		mosq->in_packet.payload = mosquitto__malloc(sizeof(uint8_t)*70);
		if(!mosq->in_packet.payload){
			mosquitto__free(packet->payload);
			mosquitto__free(packet);
			return MOSQ_ERR_NOMEM;
		}

		return packet__queue(mosq, packet);
	}else{
		// TODO: can this happen?
	}
	return MOSQ_ERR_SUCCESS;
}

int http__read(struct mosquitto *mosq)
{
	ssize_t len;
	enum mosquitto_client_state state;

	state = mosquitto__get_state(mosq);

	if(state == mosq_cs_http_start){
		while(mosq->in_packet.to_process > 0){
			len = net__read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
			if(len > 0){
				mosq->in_packet.pos += (uint32_t)len;
				mosq->in_packet.to_process -= (uint32_t)len;
			}else{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
					return MOSQ_ERR_SUCCESS;
				}else{
					packet__cleanup(&mosq->in_packet);
					switch(errno){
						case 0:
							return MOSQ_ERR_PROXY;
						case COMPAT_ECONNRESET:
							return MOSQ_ERR_CONN_LOST;
						default:
							return MOSQ_ERR_ERRNO;
					}
				}
			}
		}

		/* Entire packet is now read. */
		packet__cleanup(&mosq->in_packet);
		mosquitto__set_state(mosq, mosq_cs_new);
		if(mosq->http_host){ // TODO: Why this if here?
			int rc = net__socket_connect_step3(mosq, mosq->host);
			if(rc) return rc;
		}
		return send__connect(mosq, mosq->keepalive, mosq->clean_start, NULL);
	}else{
		return packet__read(mosq);
	}

	return MOSQ_ERR_SUCCESS;
}
#endif
