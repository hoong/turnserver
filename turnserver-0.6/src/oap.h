#include <stdint.h>


int oap_init(char* server,int passport);
void oap_exit();

int oap_checkSession(const char* session_id,uint16_t size, uint64_t uid);

