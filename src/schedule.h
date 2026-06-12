#ifndef SCHEDULE_H
#define SCHEDULE_H

// Checks if the current local time falls within:
// - Work hours: 09:30 to 16:30 (4:30 PM)
// - Sleep hours: 00:00 to 07:00
bool IsInFocusHours();

#endif // SCHEDULE_H
