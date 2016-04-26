{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE CPP #-}

{- |
Module      : System.Linux.Seccomp
Stability   : provisional
Portability : non-portable (requires Linux)

This module provides partial bindings to libseccomp. It is very low
level, modeled somewhat after the c library.

Requires kernel 3.13 with backported seccomp or newer.

Missing:

 * arch support
 * name resolving for syscalls (we have an enum)

Simple example: The following kills all systemcalls other than opening
a file for readonly:

> ctx <- S.seccomp_init S.SCMP_ACT_KILL
> _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_KILL S.SCopen [S.ArgCmp 1 S.MASQUED_EQ 0x3 0x1]
> _ <- S.seccomp_load ctx
> S.seccomp_release ctx

For debugging it's useful to dump a text representation of the filter
context to stderr (file descriptor number 2):

> S.seccomp_export_pfc ctx 2

-}
module System.Linux.Seccomp
   ( seccomp_init
   , seccomp_reset
   , seccomp_rule_add_array
   , seccomp_load
   , seccomp_merge
   , seccomp_export_pfc
   , seccomp_release
   , seccomp_syscall_priority
   , Action(..)
   , SysCall(..)
   , ArgCmp(..)
   , ArgCmpOp(..)
   , FilterContext
   ) where

import Foreign
import Foreign.C.Types
import Prelude (IO, ($), length, fromIntegral, undefined)

-- the unistd.h is necessary because it defines the architecture
-- specific __NR_open system call values. Without this seccomp will
-- set the wrong values.
#include <unistd.h>
#include <seccomp.h>

data Action =
      SCMP_ACT_KILL
    | SCMP_ACT_TRAP
    | SCMP_ACT_ERRNO Int
    | SCMP_ACT_TRACE Int
    | SCMP_ACT_ALLOW

type CFilterCtx = ()
type FilterContext = Ptr CFilterCtx

seccomp_init :: Action -> IO (Ptr CFilterCtx)
seccomp_init action = c_seccomp_init (actionToC action)

seccomp_release :: Ptr CFilterCtx -> IO ()
seccomp_release = c_seccomp_release

seccomp_reset :: Ptr CFilterCtx -> Action -> IO CInt
seccomp_reset ctx action = c_seccomp_reset ctx (actionToC action)

seccomp_load ::  Ptr CFilterCtx -> IO CInt
seccomp_load ctx = c_seccomp_load ctx

seccomp_merge ::  Ptr CFilterCtx -> Ptr CFilterCtx -> IO CInt
seccomp_merge dst src = c_seccomp_merge dst src

seccomp_syscall_priority :: Ptr CFilterCtx -> SysCall -> Word8 -> IO CInt
seccomp_syscall_priority ctx sysCall priority = c_seccomp_syscall_priority ctx (sysCallToC sysCall) priority

seccomp_export_pfc :: Ptr CFilterCtx -> Int -> IO CInt
seccomp_export_pfc ctx fd = c_seccomp_export_pfc ctx (fromIntegral fd)

seccomp_rule_add_array :: Ptr CFilterCtx -> Action -> SysCall -> [ArgCmp] -> IO CInt
seccomp_rule_add_array ctx action sysCall argCmps =
    allocaArray (length argCmps) add
  where
    add ptr = do
        pokeArray ptr argCmps
        c_seccomp_rule_add_array
          ctx
          (actionToC action)
          (sysCallToC sysCall)
          (fromIntegral (length argCmps))
          ptr

--  scmp_filter_ctx seccomp_init(uint32_t def_action);
foreign import ccall unsafe "seccomp_init"
    c_seccomp_init :: CULong -> IO (Ptr CFilterCtx)

--  void seccomp_release(scmp_filter_ctx ctx);
foreign import ccall unsafe "seccomp_release"
    c_seccomp_release :: Ptr CFilterCtx -> IO ()

foreign import ccall "seccomp_reset"
    c_seccomp_reset :: Ptr CFilterCtx -> CULong -> IO CInt

foreign import ccall "seccomp_merge"
    c_seccomp_merge :: Ptr CFilterCtx -> Ptr CFilterCtx -> IO CInt

-- int seccomp_syscall_priority(scmp_filter_ctx ctx,
--                              int syscall, uint8_t priority);
foreign import ccall "seccomp_syscall_priority"
    c_seccomp_syscall_priority :: Ptr CFilterCtx -> CLong -> Word8 -> IO CInt

-- int seccomp_rule_add_array(scmp_filter_ctx ctx,
--                            uint32_t action, int syscall,
--                            unsigned int arg_cnt,
--                            const struct scmp_arg_cmp *arg_array);
foreign import ccall "seccomp_rule_add_array"
    c_seccomp_rule_add_array :: Ptr CFilterCtx -> CULong -> CLong -> CInt -> Ptr ArgCmp -> IO CInt

foreign import ccall "seccomp_load"
    c_seccomp_load :: Ptr CFilterCtx -> IO CInt

foreign import ccall "seccomp_export_pfc"
    c_seccomp_export_pfc :: Ptr CFilterCtx -> CInt -> IO CInt

--data ArgumentPosition = A0 | A1 | A2 | A3 | A4 | A5

data ArgCmpOp = NE | LT | LE | EQ | GE | GT | MASQUED_EQ
data ArgCmp = ArgCmp
    { argCmpPos :: Int
    , argCmpOp :: ArgCmpOp
    , argCmpDatumA :: Int
    , argCmpDatumB :: Int
    }

argCmpOpToCInt :: ArgCmpOp -> CInt
argCmpOpToCInt NE = #const SCMP_CMP_NE
argCmpOpToCInt LT = #const SCMP_CMP_LT
argCmpOpToCInt LE = #const SCMP_CMP_LE
argCmpOpToCInt EQ = #const SCMP_CMP_EQ
argCmpOpToCInt GE = #const SCMP_CMP_GE
argCmpOpToCInt GT = #const SCMP_CMP_GT
argCmpOpToCInt MASQUED_EQ = #const SCMP_CMP_MASKED_EQ

-- #define SCMP_ACT_KILL           0x00000000U
-- /**
--  * Throw a SIGSYS signal
--  */
-- #define SCMP_ACT_TRAP           0x00030000U
-- /**
--  * Return the specified error code
--  */
-- #define SCMP_ACT_ERRNO(x)       (0x00050000U | ((x) & 0x0000ffffU))
-- /**
--  * Notify a tracing process with the specified value
--  */
-- #define SCMP_ACT_TRACE(x)       (0x7ff00000U | ((x) & 0x0000ffffU))
-- /**
--  * Allow the syscall to be executed
--  */
-- #define SCMP_ACT_ALLOW          0x7fff0000U
actionToC :: Action -> CULong
actionToC SCMP_ACT_KILL = 0x00000000
actionToC SCMP_ACT_TRAP = 0x00030000
actionToC (SCMP_ACT_ERRNO x) = 0x00050000 .|. ((fromIntegral x) .&. 0x0000ffff)
actionToC (SCMP_ACT_TRACE x) = 0x7ff00000 .|. ((fromIntegral x) .&. 0x0000ffff)
actionToC SCMP_ACT_ALLOW = 0x7fff0000

instance Storable ArgCmp where
    sizeOf _ = #{size struct scmp_arg_cmp}
    alignment _ = alignment (undefined :: CInt)

    peek = undefined -- Not needed, libseccomp has its own pretty printer
    poke p cmp = do
        #{poke struct scmp_arg_cmp, arg} p $ argCmpPos cmp
        #{poke struct scmp_arg_cmp, op} p $ argCmpOpToCInt (argCmpOp cmp)
        #{poke struct scmp_arg_cmp, datum_a} p $ argCmpDatumA cmp
        #{poke struct scmp_arg_cmp, datum_b} p $ argCmpDatumB cmp


data SysCall =
      SCio_setup
    | SCio_destroy
    | SCio_submit
    | SCio_cancel
    | SCio_getevents
    | SCsetxattr
    | SClsetxattr
    | SCfsetxattr
    | SCgetxattr
    | SClgetxattr
    | SCfgetxattr
    | SClistxattr
    | SCllistxattr
    | SCflistxattr
    | SCremovexattr
    | SClremovexattr
    | SCfremovexattr
    | SCgetcwd
    | SClookup_dcookie
    | SCeventfd2
    | SCepoll_create1
    | SCepoll_ctl
    | SCepoll_pwait
    | SCdup
    | SCdup3
    | SCinotify_init1
    | SCinotify_add_watch
    | SCinotify_rm_watch
    | SCioctl
    | SCioprio_set
    | SCioprio_get
    | SCflock
    | SCmknodat
    | SCmkdirat
    | SCunlinkat
    | SCsymlinkat
    | SClinkat
    | SCrenameat
    | SCumount2
    | SCmount
    | SCpivot_root
    | SCnfsservctl
    | SCfallocate
    | SCfaccessat
    | SCchdir
    | SCfchdir
    | SCchroot
    | SCfchmod
    | SCfchmodat
    | SCfchownat
    | SCfchown
    | SCopenat
    | SCclose
    | SCvhangup
    | SCpipe2
    | SCquotactl
    | SCgetdents64
    | SCread
    | SCwrite
    | SCreadv
    | SCwritev
    | SCpread64
    | SCpwrite64
    | SCpreadv
    | SCpwritev
    | SCpselect6
    | SCppoll
    | SCsignalfd4
    | SCvmsplice
    | SCsplice
    | SCtee
    | SCreadlinkat
    | SCsync
    | SCfsync
    | SCfdatasync
    | SCsync_file_range2
    | SCsync_file_range
-- TODO enable when we force minimum kernel version to be > 3.13.
--    | SCtimerfd_create
--    | SCtimerfd_settime
--    | SCtimerfd_gettime
    | SCutimensat
    | SCacct
    | SCcapget
    | SCcapset
    | SCpersonality
    | SCexit
    | SCexit_group
    | SCwaitid
    | SCset_tid_address
    | SCunshare
    | SCfutex
    | SCset_robust_list
    | SCget_robust_list
    | SCnanosleep
    | SCgetitimer
    | SCsetitimer
-- TODO enable when we force minimum kernel version to be > 3.13.
--    | SCkexec_load
    | SCinit_module
    | SCdelete_module
    | SCtimer_create
    | SCtimer_gettime
    | SCtimer_getoverrun
    | SCtimer_settime
    | SCtimer_delete
    | SCclock_settime
    | SCclock_gettime
    | SCclock_getres
    | SCclock_nanosleep
    | SCsyslog
    | SCptrace
    | SCsched_setparam
    | SCsched_setscheduler
    | SCsched_getscheduler
    | SCsched_getparam
    | SCsched_setaffinity
    | SCsched_getaffinity
    | SCsched_yield
    | SCsched_get_priority_max
    | SCsched_get_priority_min
    | SCsched_rr_get_interval
    | SCrestart_syscall
    | SCkill
    | SCtkill
    | SCtgkill
    | SCsigaltstack
    | SCrt_sigsuspend
    | SCrt_sigaction
    | SCrt_sigprocmask
    | SCrt_sigpending
    | SCrt_sigtimedwait
    | SCrt_sigqueueinfo
    | SCrt_sigreturn
    | SCsetpriority
    | SCgetpriority
    | SCreboot
    | SCsetregid
    | SCsetgid
    | SCsetreuid
    | SCsetuid
    | SCsetresuid
    | SCgetresuid
    | SCsetresgid
    | SCgetresgid
    | SCsetfsuid
    | SCsetfsgid
    | SCtimes
    | SCsetpgid
    | SCgetpgid
    | SCgetsid
    | SCsetsid
    | SCgetgroups
    | SCsetgroups
    | SCuname
    | SCsethostname
    | SCsetdomainname
    | SCgetrlimit
    | SCsetrlimit
    | SCgetrusage
    | SCumask
    | SCprctl
    | SCgetcpu
    | SCgettimeofday
    | SCsettimeofday
    | SCadjtimex
    | SCgetpid
    | SCgetppid
    | SCgetuid
    | SCgeteuid
    | SCgetgid
    | SCgetegid
    | SCgettid
    | SCsysinfo
    | SCmq_open
    | SCmq_unlink
    | SCmq_timedsend
    | SCmq_timedreceive
    | SCmq_notify
    | SCmq_getsetattr
    | SCmsgget
    | SCmsgctl
    | SCmsgrcv
    | SCmsgsnd
    | SCsemget
    | SCsemctl
    | SCsemtimedop
    | SCsemop
    | SCshmget
    | SCshmctl
    | SCshmat
    | SCshmdt
    | SCsocket
    | SCsocketpair
    | SCbind
    | SClisten
    | SCaccept
    | SCconnect
    | SCgetsockname
    | SCgetpeername
    | SCsendto
    | SCrecvfrom
    | SCsetsockopt
    | SCgetsockopt
    | SCshutdown
    | SCsendmsg
    | SCrecvmsg
    | SCreadahead
    | SCbrk
    | SCmunmap
    | SCmremap
    | SCadd_key
    | SCrequest_key
    | SCkeyctl
    | SCclone
    | SCexecve
    | SCswapon
    | SCswapoff
    | SCmprotect
    | SCmsync
    | SCmlock
    | SCmunlock
    | SCmlockall
    | SCmunlockall
    | SCmincore
    | SCmadvise
    | SCremap_file_pages
    | SCmbind
    | SCget_mempolicy
    | SCset_mempolicy
    | SCmigrate_pages
    | SCmove_pages
    | SCrt_tgsigqueueinfo
    | SCperf_event_open
    | SCaccept4
    | SCrecvmmsg
    | SCwait4
    | SCprlimit64
    | SCfanotify_init
    | SCfanotify_mark
    | SCname_to_handle_at
    | SCopen_by_handle_at
    | SCclock_adjtime
    | SCsyncfs
    | SCsetns
    | SCsendmmsg
    | SCprocess_vm_readv
    | SCprocess_vm_writev
    | SCkcmp
    | SCfinit_module
--    | SCsched_setattr
--    | SCsched_getattr
--    | SCrenameat2
    | SCopen
    | SClink
    | SCunlink
    | SCmknod
    | SCchmod
    | SCchown
    | SCmkdir
    | SCrmdir
    | SClchown
    | SCaccess
    | SCrename
    | SCreadlink
    | SCsymlink
    | SCutimes
    | SCpipe
    | SCdup2
    | SCepoll_create
    | SCinotify_init
    | SCeventfd
    | SCsignalfd
    | SCsendfile
    | SCftruncate
    | SCtruncate
    | SCfstat
    | SCfcntl
    | SCfstatfs
    | SCstatfs
    | SCalarm
    | SCgetpgrp
    | SCpause
    | SCtime
    | SCutime
    | SCcreat
    | SCgetdents
    | SCfutimesat
    | SCselect
    | SCpoll
    | SCepoll_wait
    | SCustat
    | SCvfork
    | SCrecv
    | SCsend
    | SCbdflush
    | SCumount
    | SCuselib
    | SC_sysctl
    | SCfork
    | SClseek
    | SCnewfstatat
    | SCmmap
    | SCfadvise64
    | SCstat
    | SClstat
    | SCfcntl64
    | SCtruncate64
    | SCftruncate64
    | SCsendfile64
    | SCfstatat64
    | SCfstat64
    | SCmmap2
    | SCfadvise64_64
    | SCstat64
    | SClstat64

sysCallToC :: SysCall -> CLong
sysCallToC x = case x of
    SCio_setup -> #const SCMP_SYS(io_setup)
    SCio_destroy -> #const SCMP_SYS(io_destroy)
    SCio_submit -> #const SCMP_SYS(io_submit)
    SCio_cancel -> #const SCMP_SYS(io_cancel)
    SCio_getevents -> #const SCMP_SYS(io_getevents)
    SCsetxattr -> #const SCMP_SYS(setxattr)
    SClsetxattr -> #const SCMP_SYS(lsetxattr)
    SCfsetxattr -> #const SCMP_SYS(fsetxattr)
    SCgetxattr -> #const SCMP_SYS(getxattr)
    SClgetxattr -> #const SCMP_SYS(lgetxattr)
    SCfgetxattr -> #const SCMP_SYS(fgetxattr)
    SClistxattr -> #const SCMP_SYS(listxattr)
    SCllistxattr -> #const SCMP_SYS(llistxattr)
    SCflistxattr -> #const SCMP_SYS(flistxattr)
    SCremovexattr -> #const SCMP_SYS(removexattr)
    SClremovexattr -> #const SCMP_SYS(lremovexattr)
    SCfremovexattr -> #const SCMP_SYS(fremovexattr)
    SCgetcwd -> #const SCMP_SYS(getcwd)
    SClookup_dcookie -> #const SCMP_SYS(lookup_dcookie)
    SCeventfd2 -> #const SCMP_SYS(eventfd2)
    SCepoll_create1 -> #const SCMP_SYS(epoll_create1)
    SCepoll_ctl -> #const SCMP_SYS(epoll_ctl)
    SCepoll_pwait -> #const SCMP_SYS(epoll_pwait)
    SCdup -> #const SCMP_SYS(dup)
    SCdup3 -> #const SCMP_SYS(dup3)
    SCinotify_init1 -> #const SCMP_SYS(inotify_init1)
    SCinotify_add_watch -> #const SCMP_SYS(inotify_add_watch)
    SCinotify_rm_watch -> #const SCMP_SYS(inotify_rm_watch)
    SCioctl -> #const SCMP_SYS(ioctl)
    SCioprio_set -> #const SCMP_SYS(ioprio_set)
    SCioprio_get -> #const SCMP_SYS(ioprio_get)
    SCflock -> #const SCMP_SYS(flock)
    SCmknodat -> #const SCMP_SYS(mknodat)
    SCmkdirat -> #const SCMP_SYS(mkdirat)
    SCunlinkat -> #const SCMP_SYS(unlinkat)
    SCsymlinkat -> #const SCMP_SYS(symlinkat)
    SClinkat -> #const SCMP_SYS(linkat)
    SCrenameat -> #const SCMP_SYS(renameat)
    SCumount2 -> #const SCMP_SYS(umount2)
    SCmount -> #const SCMP_SYS(mount)
    SCpivot_root -> #const SCMP_SYS(pivot_root)
    SCnfsservctl -> #const SCMP_SYS(nfsservctl)
    SCfallocate -> #const SCMP_SYS(fallocate)
    SCfaccessat -> #const SCMP_SYS(faccessat)
    SCchdir -> #const SCMP_SYS(chdir)
    SCfchdir -> #const SCMP_SYS(fchdir)
    SCchroot -> #const SCMP_SYS(chroot)
    SCfchmod -> #const SCMP_SYS(fchmod)
    SCfchmodat -> #const SCMP_SYS(fchmodat)
    SCfchownat -> #const SCMP_SYS(fchownat)
    SCfchown -> #const SCMP_SYS(fchown)
    SCopenat -> #const SCMP_SYS(openat)
    SCclose -> #const SCMP_SYS(close)
    SCvhangup -> #const SCMP_SYS(vhangup)
    SCpipe2 -> #const SCMP_SYS(pipe2)
    SCquotactl -> #const SCMP_SYS(quotactl)
    SCgetdents64 -> #const SCMP_SYS(getdents64)
    SCread -> #const SCMP_SYS(read)
    SCwrite -> #const SCMP_SYS(write)
    SCreadv -> #const SCMP_SYS(readv)
    SCwritev -> #const SCMP_SYS(writev)
    SCpread64 -> #const SCMP_SYS(pread64)
    SCpwrite64 -> #const SCMP_SYS(pwrite64)
    SCpreadv -> #const SCMP_SYS(preadv)
    SCpwritev -> #const SCMP_SYS(pwritev)
    SCpselect6 -> #const SCMP_SYS(pselect6)
    SCppoll -> #const SCMP_SYS(ppoll)
    SCsignalfd4 -> #const SCMP_SYS(signalfd4)
    SCvmsplice -> #const SCMP_SYS(vmsplice)
    SCsplice -> #const SCMP_SYS(splice)
    SCtee -> #const SCMP_SYS(tee)
    SCreadlinkat -> #const SCMP_SYS(readlinkat)
    SCsync -> #const SCMP_SYS(sync)
    SCfsync -> #const SCMP_SYS(fsync)
    SCfdatasync -> #const SCMP_SYS(fdatasync)
    SCsync_file_range2 -> #const SCMP_SYS(sync_file_range2)
    SCsync_file_range -> #const SCMP_SYS(sync_file_range)
--    SCtimerfd_create -> #const SCMP_SYS(timerfd_create)
--    SCtimerfd_settime -> #const SCMP_SYS(timerfd_settime)
--    SCtimerfd_gettime -> #const SCMP_SYS(timerfd_gettime)
    SCutimensat -> #const SCMP_SYS(utimensat)
    SCacct -> #const SCMP_SYS(acct)
    SCcapget -> #const SCMP_SYS(capget)
    SCcapset -> #const SCMP_SYS(capset)
    SCpersonality -> #const SCMP_SYS(personality)
    SCexit -> #const SCMP_SYS(exit)
    SCexit_group -> #const SCMP_SYS(exit_group)
    SCwaitid -> #const SCMP_SYS(waitid)
    SCset_tid_address -> #const SCMP_SYS(set_tid_address)
    SCunshare -> #const SCMP_SYS(unshare)
    SCfutex -> #const SCMP_SYS(futex)
    SCset_robust_list -> #const SCMP_SYS(set_robust_list)
    SCget_robust_list -> #const SCMP_SYS(get_robust_list)
    SCnanosleep -> #const SCMP_SYS(nanosleep)
    SCgetitimer -> #const SCMP_SYS(getitimer)
    SCsetitimer -> #const SCMP_SYS(setitimer)
--    SCkexec_load -> #const SCMP_SYS(kexec_load)
    SCinit_module -> #const SCMP_SYS(init_module)
    SCdelete_module -> #const SCMP_SYS(delete_module)
    SCtimer_create -> #const SCMP_SYS(timer_create)
    SCtimer_gettime -> #const SCMP_SYS(timer_gettime)
    SCtimer_getoverrun -> #const SCMP_SYS(timer_getoverrun)
    SCtimer_settime -> #const SCMP_SYS(timer_settime)
    SCtimer_delete -> #const SCMP_SYS(timer_delete)
    SCclock_settime -> #const SCMP_SYS(clock_settime)
    SCclock_gettime -> #const SCMP_SYS(clock_gettime)
    SCclock_getres -> #const SCMP_SYS(clock_getres)
    SCclock_nanosleep -> #const SCMP_SYS(clock_nanosleep)
    SCsyslog -> #const SCMP_SYS(syslog)
    SCptrace -> #const SCMP_SYS(ptrace)
    SCsched_setparam -> #const SCMP_SYS(sched_setparam)
    SCsched_setscheduler -> #const SCMP_SYS(sched_setscheduler)
    SCsched_getscheduler -> #const SCMP_SYS(sched_getscheduler)
    SCsched_getparam -> #const SCMP_SYS(sched_getparam)
    SCsched_setaffinity -> #const SCMP_SYS(sched_setaffinity)
    SCsched_getaffinity -> #const SCMP_SYS(sched_getaffinity)
    SCsched_yield -> #const SCMP_SYS(sched_yield)
    SCsched_get_priority_max -> #const SCMP_SYS(sched_get_priority_max)
    SCsched_get_priority_min -> #const SCMP_SYS(sched_get_priority_min)
    SCsched_rr_get_interval -> #const SCMP_SYS(sched_rr_get_interval)
    SCrestart_syscall -> #const SCMP_SYS(restart_syscall)
    SCkill -> #const SCMP_SYS(kill)
    SCtkill -> #const SCMP_SYS(tkill)
    SCtgkill -> #const SCMP_SYS(tgkill)
    SCsigaltstack -> #const SCMP_SYS(sigaltstack)
    SCrt_sigsuspend -> #const SCMP_SYS(rt_sigsuspend)
    SCrt_sigaction -> #const SCMP_SYS(rt_sigaction)
    SCrt_sigprocmask -> #const SCMP_SYS(rt_sigprocmask)
    SCrt_sigpending -> #const SCMP_SYS(rt_sigpending)
    SCrt_sigtimedwait -> #const SCMP_SYS(rt_sigtimedwait)
    SCrt_sigqueueinfo -> #const SCMP_SYS(rt_sigqueueinfo)
    SCrt_sigreturn -> #const SCMP_SYS(rt_sigreturn)
    SCsetpriority -> #const SCMP_SYS(setpriority)
    SCgetpriority -> #const SCMP_SYS(getpriority)
    SCreboot -> #const SCMP_SYS(reboot)
    SCsetregid -> #const SCMP_SYS(setregid)
    SCsetgid -> #const SCMP_SYS(setgid)
    SCsetreuid -> #const SCMP_SYS(setreuid)
    SCsetuid -> #const SCMP_SYS(setuid)
    SCsetresuid -> #const SCMP_SYS(setresuid)
    SCgetresuid -> #const SCMP_SYS(getresuid)
    SCsetresgid -> #const SCMP_SYS(setresgid)
    SCgetresgid -> #const SCMP_SYS(getresgid)
    SCsetfsuid -> #const SCMP_SYS(setfsuid)
    SCsetfsgid -> #const SCMP_SYS(setfsgid)
    SCtimes -> #const SCMP_SYS(times)
    SCsetpgid -> #const SCMP_SYS(setpgid)
    SCgetpgid -> #const SCMP_SYS(getpgid)
    SCgetsid -> #const SCMP_SYS(getsid)
    SCsetsid -> #const SCMP_SYS(setsid)
    SCgetgroups -> #const SCMP_SYS(getgroups)
    SCsetgroups -> #const SCMP_SYS(setgroups)
    SCuname -> #const SCMP_SYS(uname)
    SCsethostname -> #const SCMP_SYS(sethostname)
    SCsetdomainname -> #const SCMP_SYS(setdomainname)
    SCgetrlimit -> #const SCMP_SYS(getrlimit)
    SCsetrlimit -> #const SCMP_SYS(setrlimit)
    SCgetrusage -> #const SCMP_SYS(getrusage)
    SCumask -> #const SCMP_SYS(umask)
    SCprctl -> #const SCMP_SYS(prctl)
    SCgetcpu -> #const SCMP_SYS(getcpu)
    SCgettimeofday -> #const SCMP_SYS(gettimeofday)
    SCsettimeofday -> #const SCMP_SYS(settimeofday)
    SCadjtimex -> #const SCMP_SYS(adjtimex)
    SCgetpid -> #const SCMP_SYS(getpid)
    SCgetppid -> #const SCMP_SYS(getppid)
    SCgetuid -> #const SCMP_SYS(getuid)
    SCgeteuid -> #const SCMP_SYS(geteuid)
    SCgetgid -> #const SCMP_SYS(getgid)
    SCgetegid -> #const SCMP_SYS(getegid)
    SCgettid -> #const SCMP_SYS(gettid)
    SCsysinfo -> #const SCMP_SYS(sysinfo)
    SCmq_open -> #const SCMP_SYS(mq_open)
    SCmq_unlink -> #const SCMP_SYS(mq_unlink)
    SCmq_timedsend -> #const SCMP_SYS(mq_timedsend)
    SCmq_timedreceive -> #const SCMP_SYS(mq_timedreceive)
    SCmq_notify -> #const SCMP_SYS(mq_notify)
    SCmq_getsetattr -> #const SCMP_SYS(mq_getsetattr)
    SCmsgget -> #const SCMP_SYS(msgget)
    SCmsgctl -> #const SCMP_SYS(msgctl)
    SCmsgrcv -> #const SCMP_SYS(msgrcv)
    SCmsgsnd -> #const SCMP_SYS(msgsnd)
    SCsemget -> #const SCMP_SYS(semget)
    SCsemctl -> #const SCMP_SYS(semctl)
    SCsemtimedop -> #const SCMP_SYS(semtimedop)
    SCsemop -> #const SCMP_SYS(semop)
    SCshmget -> #const SCMP_SYS(shmget)
    SCshmctl -> #const SCMP_SYS(shmctl)
    SCshmat -> #const SCMP_SYS(shmat)
    SCshmdt -> #const SCMP_SYS(shmdt)
    SCsocket -> #const SCMP_SYS(socket)
    SCsocketpair -> #const SCMP_SYS(socketpair)
    SCbind -> #const SCMP_SYS(bind)
    SClisten -> #const SCMP_SYS(listen)
    SCaccept -> #const SCMP_SYS(accept)
    SCconnect -> #const SCMP_SYS(connect)
    SCgetsockname -> #const SCMP_SYS(getsockname)
    SCgetpeername -> #const SCMP_SYS(getpeername)
    SCsendto -> #const SCMP_SYS(sendto)
    SCrecvfrom -> #const SCMP_SYS(recvfrom)
    SCsetsockopt -> #const SCMP_SYS(setsockopt)
    SCgetsockopt -> #const SCMP_SYS(getsockopt)
    SCshutdown -> #const SCMP_SYS(shutdown)
    SCsendmsg -> #const SCMP_SYS(sendmsg)
    SCrecvmsg -> #const SCMP_SYS(recvmsg)
    SCreadahead -> #const SCMP_SYS(readahead)
    SCbrk -> #const SCMP_SYS(brk)
    SCmunmap -> #const SCMP_SYS(munmap)
    SCmremap -> #const SCMP_SYS(mremap)
    SCadd_key -> #const SCMP_SYS(add_key)
    SCrequest_key -> #const SCMP_SYS(request_key)
    SCkeyctl -> #const SCMP_SYS(keyctl)
    SCclone -> #const SCMP_SYS(clone)
    SCexecve -> #const SCMP_SYS(execve)
    SCswapon -> #const SCMP_SYS(swapon)
    SCswapoff -> #const SCMP_SYS(swapoff)
    SCmprotect -> #const SCMP_SYS(mprotect)
    SCmsync -> #const SCMP_SYS(msync)
    SCmlock -> #const SCMP_SYS(mlock)
    SCmunlock -> #const SCMP_SYS(munlock)
    SCmlockall -> #const SCMP_SYS(mlockall)
    SCmunlockall -> #const SCMP_SYS(munlockall)
    SCmincore -> #const SCMP_SYS(mincore)
    SCmadvise -> #const SCMP_SYS(madvise)
    SCremap_file_pages -> #const SCMP_SYS(remap_file_pages)
    SCmbind -> #const SCMP_SYS(mbind)
    SCget_mempolicy -> #const SCMP_SYS(get_mempolicy)
    SCset_mempolicy -> #const SCMP_SYS(set_mempolicy)
    SCmigrate_pages -> #const SCMP_SYS(migrate_pages)
    SCmove_pages -> #const SCMP_SYS(move_pages)
    SCrt_tgsigqueueinfo -> #const SCMP_SYS(rt_tgsigqueueinfo)
    SCperf_event_open -> #const SCMP_SYS(perf_event_open)
    SCaccept4 -> #const SCMP_SYS(accept4)
    SCrecvmmsg -> #const SCMP_SYS(recvmmsg)
    SCwait4 -> #const SCMP_SYS(wait4)
    SCprlimit64 -> #const SCMP_SYS(prlimit64)
    SCfanotify_init -> #const SCMP_SYS(fanotify_init)
    SCfanotify_mark -> #const SCMP_SYS(fanotify_mark)
    SCname_to_handle_at -> #const SCMP_SYS(name_to_handle_at)
    SCopen_by_handle_at -> #const SCMP_SYS(open_by_handle_at)
    SCclock_adjtime -> #const SCMP_SYS(clock_adjtime)
    SCsyncfs -> #const SCMP_SYS(syncfs)
    SCsetns -> #const SCMP_SYS(setns)
    SCsendmmsg -> #const SCMP_SYS(sendmmsg)
    SCprocess_vm_readv -> #const SCMP_SYS(process_vm_readv)
    SCprocess_vm_writev -> #const SCMP_SYS(process_vm_writev)
    SCkcmp -> #const SCMP_SYS(kcmp)
    SCfinit_module -> #const SCMP_SYS(finit_module)
--    SCsched_setattr -> #const SCMP_SYS(sched_setattr)
--    SCsched_getattr -> #const SCMP_SYS(sched_getattr)
--    SCrenameat2 -> #const SCMP_SYS(renameat2)
    SCopen -> #const SCMP_SYS(open)
    SClink -> #const SCMP_SYS(link)
    SCunlink -> #const SCMP_SYS(unlink)
    SCmknod -> #const SCMP_SYS(mknod)
    SCchmod -> #const SCMP_SYS(chmod)
    SCchown -> #const SCMP_SYS(chown)
    SCmkdir -> #const SCMP_SYS(mkdir)
    SCrmdir -> #const SCMP_SYS(rmdir)
    SClchown -> #const SCMP_SYS(lchown)
    SCaccess -> #const SCMP_SYS(access)
    SCrename -> #const SCMP_SYS(rename)
    SCreadlink -> #const SCMP_SYS(readlink)
    SCsymlink -> #const SCMP_SYS(symlink)
    SCutimes -> #const SCMP_SYS(utimes)
    SCpipe -> #const SCMP_SYS(pipe)
    SCdup2 -> #const SCMP_SYS(dup2)
    SCepoll_create -> #const SCMP_SYS(epoll_create)
    SCinotify_init -> #const SCMP_SYS(inotify_init)
    SCeventfd -> #const SCMP_SYS(eventfd)
    SCsignalfd -> #const SCMP_SYS(signalfd)
    SCfcntl -> #const SCMP_SYS(fcntl)
    SCfadvise64 -> #const SCMP_SYS(fadvise64)
    SCalarm -> #const SCMP_SYS(alarm)
    SCgetpgrp -> #const SCMP_SYS(getpgrp)
    SCpause -> #const SCMP_SYS(pause)
    SCtime -> #const SCMP_SYS(time)
    SCutime -> #const SCMP_SYS(utime)
    SCcreat -> #const SCMP_SYS(creat)
    SCgetdents -> #const SCMP_SYS(getdents)
    SCfutimesat -> #const SCMP_SYS(futimesat)
    SCselect -> #const SCMP_SYS(select)
    SCpoll -> #const SCMP_SYS(poll)
    SCepoll_wait -> #const SCMP_SYS(epoll_wait)
    SCustat -> #const SCMP_SYS(ustat)
    SCvfork -> #const SCMP_SYS(vfork)
    SCrecv -> #const SCMP_SYS(recv)
    SCsend -> #const SCMP_SYS(send)
    SCbdflush -> #const SCMP_SYS(bdflush)
    SCumount -> #const SCMP_SYS(umount)
    SCuselib -> #const SCMP_SYS(uselib)
    SC_sysctl -> #const SCMP_SYS(_sysctl)
    SCfork -> #const SCMP_SYS(fork)
    SCstatfs -> #const SCMP_SYS(statfs)
    SCfstatfs -> #const SCMP_SYS(fstatfs)
    SCtruncate -> #const SCMP_SYS(truncate)
    SCftruncate -> #const SCMP_SYS(ftruncate)
    SClseek -> #const SCMP_SYS(lseek)
    SCsendfile -> #const SCMP_SYS(sendfile)
    SCnewfstatat -> #const SCMP_SYS(newfstatat)
    SCfstat -> #const SCMP_SYS(fstat)
    SCmmap -> #const SCMP_SYS(mmap)
    SCstat -> #const SCMP_SYS(stat)
    SClstat -> #const SCMP_SYS(lstat)
    SCfcntl64 -> #const SCMP_SYS(fcntl64)
    SCtruncate64 -> #const SCMP_SYS(truncate64)
    SCftruncate64 -> #const SCMP_SYS(ftruncate64)
    SCsendfile64 -> #const SCMP_SYS(sendfile64)
    SCfstatat64 -> #const SCMP_SYS(fstatat64)
    SCfstat64 -> #const SCMP_SYS(fstat64)
    SCmmap2 -> #const SCMP_SYS(mmap2)
    SCfadvise64_64 -> #const SCMP_SYS(fadvise64_64)
    SCstat64 -> #const SCMP_SYS(stat64)
    SClstat64 -> #const SCMP_SYS(lstat64)
