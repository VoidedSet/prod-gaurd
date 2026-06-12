#include "schedule.h"
#include <windows.h>

bool IsInFocusHours()
{
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    int current_minutes = lt.wHour * 60 + lt.wMinute;

    // Work Hours: 09:30 to 16:30 (570 to 990 minutes)
    int work_start = 9 * 60 + 30; // 570
    int work_end = 16 * 60 + 30;  // 990

    if (current_minutes >= work_start && current_minutes <= work_end)
    {
        return true;
    }

    // Sleep Hours: 00:00 to 07:00 (0 to 420 minutes)
    int sleep_start = 0 * 60 + 0; // 0
    int sleep_end = 7 * 60 + 0;   // 420

    if (current_minutes >= sleep_start && current_minutes <= sleep_end)
    {
        return true;
    }

    return false;
}
