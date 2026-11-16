#include "module_tls_http.h"

ModuleTlsHttpProvider::ModuleTlsHttpProvider(ModuleTlsPort& port, uint32_t exchange_ms, uint32_t cleanup_ms) :
    port_(port), exchange_ms_(exchange_ms), cleanup_ms_(cleanup_ms), occupied_(false) {}
bool ModuleTlsHttpProvider::available() const { return false; }
HttpConnection *ModuleTlsHttpProvider::create_connection(const OperationCancellation&) { return 0; }
