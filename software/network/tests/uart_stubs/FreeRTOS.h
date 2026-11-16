#ifndef TEST_UART_FREERTOS_H
#define TEST_UART_FREERTOS_H
#include <stdint.h>
#include <assert.h>
typedef int BaseType_t;
typedef unsigned TickType_t;
typedef void *QueueHandle_t;
enum { pdFALSE = 0, pdTRUE = 1 };
extern unsigned uart_critical_depth;
#define portENTER_CRITICAL() (++uart_critical_depth)
// Scheduler suspension: while the depth is nonzero no other task may run. The test supplies these and decides
// what a task that is allowed to run does (see preempt_point in test_uart_loss.cc).
extern unsigned uart_scheduler_suspended;
void vTaskSuspendAll(void);
BaseType_t xTaskResumeAll(void);
#define portEXIT_CRITICAL() do { assert(uart_critical_depth); --uart_critical_depth; } while (0)
#endif
