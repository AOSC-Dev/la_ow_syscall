extern unsigned int debug_print;

#define DEBUG_FSTAT (1<<0)
#define DEBUG_SIGNAL (1<<1)

#ifdef CUR_DEBUG
#include <linux/delay.h>
#define __expand(x) (DEBUG_ ## x)
#define __dbg_cur(x) __expand(x)

#define DEBUG_POINT do{ \
		if (debug_print & (__dbg_cur(CUR_DEBUG))){ \
			pr_info("%s: pid=%d\n", __func__, task_pid_nr(current)); \
                	msleep_interruptible(10 * 1000); \
		}\
	}while(0)

#endif
