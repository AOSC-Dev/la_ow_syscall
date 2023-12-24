#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include "signal.h"

#define _LA_OW_NSIG 128
#define _LA_OW_NSIG_WORDS (_LA_OW_NSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_LA_OW_NSIG_WORDS];
} _la_ow_sigset_t;

static inline int clear_user_sigset_extension(sigset_t __user *to)
{
	char __user *expansion = (char __user *)to + sizeof(sigset_t);
	int rc = clear_user(expansion,
			    sizeof(_la_ow_sigset_t) - sizeof(sigset_t));
	if (rc < 0) {
		return -EFAULT;
	}
	return 0;
}

__SYSCALL_DEFINEx(4, _rt_sigprocmask, int, how, sigset_t __user *, nset,
		  sigset_t __user *, oset, size_t, sigsetsize)
{
	if (sigsetsize == sizeof(sigset_t)) {
		return p_sys_rt_sigprocmask(how, nset, oset, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc =
			p_sys_rt_sigprocmask(how, nset, oset, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		if (oset) {
			int rc2 = clear_user_sigset_extension(oset);
			if (rc2 < 0) {
				return rc2;
			}
		}
		return 0;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(2, _rt_sigpending, sigset_t __user *, uset, size_t,
		  sigsetsize)
{
	if (sigsetsize == sizeof(sigset_t)) {
		return p_sys_rt_sigpending(uset, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_rt_sigpending(uset, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		int rc2 = clear_user_sigset_extension(uset);
		if (rc2 < 0) {
			return rc2;
		}
		return 0;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(4, _rt_sigtimedwait, const sigset_t __user *, uthese,
		  siginfo_t __user *, uinfo,
		  const struct __kernel_timespec __user *, uts, size_t,
		  sigsetsize)
{
	if (sigsetsize == sizeof(sigset_t)) {
		return p_sys_rt_sigtimedwait(uthese, uinfo, uts, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_rt_sigtimedwait(uthese, uinfo, uts,
					       sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(4, _rt_sigaction, int, sig, const struct sigaction __user *,
		  act, struct sigaction __user *, oact, size_t, sigsetsize)
{
	if (sigsetsize == sizeof(sigset_t)) {
		return p_sys_rt_sigaction(sig, act, oact, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_rt_sigaction(sig, act, oact, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		if (oact) {
			int rc2 = clear_user_sigset_extension(&oact->sa_mask);
			if (rc2 < 0) {
				return rc2;
			}
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(2, _rt_sigsuspend, sigset_t __user *, unewset, size_t,
		  sigsetsize)
{
	if (sigsetsize == sizeof(sigset_t)) {
		return p_sys_rt_sigsuspend(unewset, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_rt_sigsuspend(unewset, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(6, _pselect6, int, n, fd_set __user *, inp, fd_set __user *,
		  outp, fd_set __user *, exp, struct __kernel_timespec __user *,
		  tsp, void __user *, sig)
{
	struct sigset_argpack {
		sigset_t __user *p;
		size_t size;
	} x = { NULL, 0 };
	struct sigset_argpack __user *siginfo =
		(struct sigset_argpack __user *)sig;

	if (siginfo) {
		int rc = get_user(x.size, &siginfo->size);
		if (rc < 0) {
			return -EFAULT;
		}
	}
	if (siginfo == NULL || x.size == sizeof(sigset_t)) {
		return p_sys_pselect6(n, inp, outp, exp, tsp, sig);
	} else if (x.size == sizeof(_la_ow_sigset_t)) {
		int rc = put_user(sizeof(sigset_t), &siginfo->size);
		if (rc < 0) {
			return -EFAULT;
		}
		rc = p_sys_pselect6(n, inp, outp, exp, tsp, sig);
		int rc2 = put_user(sizeof(_la_ow_sigset_t), &siginfo->size);
		if (rc2 < 0) {
			return -EFAULT;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(5, _ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
		struct __kernel_timespec __user *, tsp, const sigset_t __user *, sigmask,
		size_t, sigsetsize)
{
	if (sigmask == NULL || sigsetsize == sizeof(sigset_t)) {
		return p_sys_ppoll(ufds, nfds, tsp, sigmask, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_ppoll(ufds, nfds, tsp, sigmask, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

#ifdef CONFIG_EPOLL

__SYSCALL_DEFINEx(6, _epoll_pwait, int, epfd, struct epoll_event __user *,
		  events, int, maxevents, int, timeout, const sigset_t __user *,
		  sigmask, size_t, sigsetsize)
{
	if (sigmask == NULL || sigsetsize == sizeof(sigset_t)) {
		return p_sys_epoll_pwait(epfd, events, maxevents, timeout,
					 sigmask, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_epoll_pwait(epfd, events, maxevents, timeout,
					   sigmask, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

__SYSCALL_DEFINEx(6, _epoll_pwait2, int, epfd, struct epoll_event __user *,
		  events, int, maxevents,
		  const struct __kernel_timespec __user *, timeout,
		  const sigset_t __user *, sigmask, size_t, sigsetsize)
{
	if (sigmask == NULL || sigsetsize == sizeof(sigset_t)) {
		return p_sys_epoll_pwait2(epfd, events, maxevents, timeout,
					  sigmask, sigsetsize);
	} else if (sigsetsize == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_epoll_pwait2(epfd, events, maxevents, timeout,
					    sigmask, sizeof(sigset_t));
		if (rc < 0) {
			return rc;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

#endif

#ifdef CONFIG_SIGNALFD

__SYSCALL_DEFINEx(4, _signalfd4, int, ufd, sigset_t __user *, user_mask, size_t,
		  sizemask, int, flags)
{
	if (sizemask == sizeof(sigset_t)) {
		return p_sys_signalfd4(ufd, user_mask, sizemask, flags);
	} else if (sizemask == sizeof(_la_ow_sigset_t)) {
		int rc = p_sys_signalfd4(ufd, user_mask, sizeof(sigset_t),
					 flags);
		if (rc < 0) {
			return rc;
		}
		return rc;
	} else {
		return -EINVAL;
	}
}

#endif
