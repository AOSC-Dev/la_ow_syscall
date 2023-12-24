#include <linux/syscalls.h>

#ifndef __EXTERN
#define __EXTERN extern
#endif
#define P__SYSCALL_DEFINEx(x, name, ...) \
	__EXTERN int (*p_sys##name)(__MAP(x, __SC_DECL, __VA_ARGS__))

P__SYSCALL_DEFINEx(4, _rt_sigprocmask, int, how, sigset_t __user *, nset,
		   sigset_t __user *, oset, size_t, sigsetsize);

P__SYSCALL_DEFINEx(2, _rt_sigpending, sigset_t __user *, uset, size_t,
		   sigsetsize);

P__SYSCALL_DEFINEx(4, _rt_sigtimedwait, const sigset_t __user *, uthese,
		   siginfo_t __user *, uinfo,
		   const struct __kernel_timespec __user *, uts, size_t,
		   sigsetsize);

P__SYSCALL_DEFINEx(4, _rt_sigaction, int, sig, const struct sigaction __user *,
		   act, struct sigaction __user *, oact, size_t, sigsetsize);

P__SYSCALL_DEFINEx(2, _rt_sigsuspend, sigset_t __user *, unewset, size_t,
		   sigsetsize);
P__SYSCALL_DEFINEx(6, _pselect6, int, n, fd_set __user *, inp, fd_set __user *,
		   outp, fd_set __user *, exp,
		   struct __kernel_timespec __user *, tsp, void __user *, sig);
P__SYSCALL_DEFINEx(5, _ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
		struct __kernel_timespec __user *, tsp, const sigset_t __user *, sigmask,
		size_t, sigsetsize);
#ifdef CONFIG_SIGNALFD
P__SYSCALL_DEFINEx(4, _signalfd4, int, ufd, sigset_t __user *, user_mask,
		   size_t, sizemask, int, flags);
#endif
#ifdef CONFIG_EPOLL
P__SYSCALL_DEFINEx(6, _epoll_pwait, int, epfd, struct epoll_event __user *,
		   events, int, maxevents, int, timeout,
		   const sigset_t __user *, sigmask, size_t, sigsetsize);
P__SYSCALL_DEFINEx(6, _epoll_pwait2, int, epfd, struct epoll_event __user *,
		   events, int, maxevents,
		   const struct __kernel_timespec __user *, timeout,
		   const sigset_t __user *, sigmask, size_t, sigsetsize);
#undef P__SYSCALL_DEFINEx
#endif
