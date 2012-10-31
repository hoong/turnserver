#include "oap.h"
#include "dbg.h"
#include "util_sys.h"
#include <mjson/json.h>
#include <curl/curl.h>
#include <stdlib.h>


int req_timeout;
int conn_timeout;
int insidepassport;
char session_interface[1024];




uint64_t read_uid(json_t* root)
{
	json_t* id_node = json_find_first_label(root,"uid");
	if (id_node  && id_node->child &&
		(id_node->child->type == JSON_NUMBER) &&
		id_node->child->text)
	{
		//debug(DBG_ATTR,"uid string is :%s\n",id_node->child->text);
		return strtoull(id_node->child->text,NULL,10);
	};
	return 0;
}

int oap_init(const char*server,int passport )
{
	req_timeout = 20;
	conn_timeout = 20;
	insidepassport = passport;// for configured
	memset(session_interface,0,sizeof(session_interface));
	snprintf(session_interface,sizeof(session_interface)-1,"%s/passport/check",server);
	if (0 != curl_global_init(CURL_GLOBAL_ALL))
		return -1;

	return 0;
};

void oap_exit()
{
	curl_global_cleanup();
};


static size_t write_function(char* buffer, size_t size, size_t nmemb, char** stream)
{
	if (!stream)
		return 0;

	size_t total = size * nmemb +1;
	*stream = malloc(total);
	memset(*stream,0,total);
	memcpy(*stream,buffer,total-1);

	//stream->append(buffer, total);
	return total;
}

static size_t read_function(char* buffer, size_t size, size_t nmemb, iovec* iov)
{
	if (!iov)
		return 0;

	size_t total = size * nmemb;
	size_t toread = total < iov->iov_len ? total : iov->iov_len;
	memcpy(buffer, iov->iov_base, toread);
	iov->iov_len -= toread;
	return toread;
}

int request(const char* url, const char* method, const char* request_body, const char* cookie, int* outptr_response_code, char** outptr_response_body)
{
	if (outptr_response_code)
		*outptr_response_code = 0;
	if (outptr_response_body)
		outptr_response_body->clear();

	CURL* curl = curl_easy_init();
	if (!curl)
		return -1;

	CURLcode ret;
	ret = curl_easy_setopt(curl, CURLOPT_URL, url);
	ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT, req_timeout);
	ret = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, conn_timeout);
	ret = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	if (outptr_response_body)
	{
		ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
		ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, outptr_response_body);
	}
	if (cookie)
		ret = curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);

	iovec iov;
	if (request_body)
	{
		iov.iov_base = (void*)request_body;
		iov.iov_len = strlen(request_body);
		ret = curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_function);
		ret = curl_easy_setopt(curl, CURLOPT_READDATA, &iov);
	}

	if (strcmp(method, "POST") == 0)
		ret = curl_easy_setopt(curl, CURLOPT_POST, 1L);
	else if (strcmp(method, "PUT") == 0)
		ret = curl_easy_setopt(curl, CURLOPT_PUT, 1L);
	else
		ret = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

	if (request_body)
	{
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*)request_body);
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(request_body));
	}

	ret = curl_easy_perform(curl);

	if (ret != CURLE_OK && ret != CURLE_HTTP_RETURNED_ERROR)
		return -1;

	long http_code;
	ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (outptr_response_code)
		*outptr_response_code= http_code;

	curl_easy_cleanup(curl);
	return 0;
};

int oap_checkSession(const char* session_id, uint16_t size,uint64_t uid)
{
//	static const char url[] = "/passport/check";

//	insidepassport = CONFIGURE_MANAGER::instance()->m_oap_insidepassport;

	char szdata[1024];
	char session[64];
	uint16_t sess_len = MAX(sizeof(session),size);
	memset (session,0,sizeof(session));
	snprintf(session,sess_len ,"%s",session_id);
	snprintf(szdata, 1024, "{\"uap_sid\":\"%s\",\"insidepassport\":\"%u\"}", session, insidepassport);

	int rescode;
	char* resstr = NULL;
	int ret = request(session_interface, "POST", szdata, NULL, &rescode, &resstr);
	int return_code = 500;

	debug(DBG_ATTR,"checkSession ret=%u, rescode=%u\n", ret, rescode);

#define RETURN(x) return_code = x;goto RET

	if (0 == ret)
	{
		if (200 == rescode)
		{
			try
			{
				json_t* document = NULL;
				if (json_parse_document(&document,resstr) == JSON_OK)
				{
					if(read_uid(document) == uid )
					{
						json_free_value(document);
						RETURN(200);
					}
					json_free_value(document);
				}
			}
			catch (...)
			{
				debug(DBG_ATTR,"oap failed! bad json: %s\n", resstr.c_str());
				RETURN(500);
			}
			RETURN(401)
		}
		else
			debug(DBG_ATTR,"checkSession failed! ret=%u, rescode=%u\n", ret, rescode);

		RETURN(rescode);
	}
	else
		debug(DBG_ATTR,"checkSession failed! ret=%u\n", ret);

RET:

	if (resstr)
		free(resstr);
	return return_code;
};


