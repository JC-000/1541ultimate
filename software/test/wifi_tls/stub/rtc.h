// Host stand-in for software/io/rtc/rtc.h: the calls wifi_tls_spike.cc makes,
// faked in spike_test.cc.
#ifndef RTC_H_STUB
#define RTC_H_STUB
class Rtc
{
public:
    bool is_valid(void);
    void get_time(int &y, int &M, int &D, int &wd, int &h, int &m, int &s);
};
extern Rtc rtc;
#endif
