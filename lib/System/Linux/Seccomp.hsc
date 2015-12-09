{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE CPP #-}

{- |
Module      : System.Linux.Seccomp
Stability   : provisional
Portability : non-portable (requires Linux)

This module provides bindings libseccomp.

-}
module System.Linux.Seccomp
   ( seccomp_init
   , seccomp_reset
   , seccomp_rule_add_array
   , seccomp_load
   , seccomp_export_pfc
   , Action(..)
   , SysCall(..)
   ) where

import Foreign
import Foreign.C.Types
import Prelude (IO, ($), length, fromIntegral, undefined, print, return)

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
type CArgCmp = ()


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


seccomp_init :: Action -> IO (Ptr CFilterCtx)
seccomp_init action = c_seccomp_init (actionToC action)

seccomp_reset :: Ptr CFilterCtx -> Action -> IO CInt
seccomp_reset ctx action = c_seccomp_reset ctx (actionToC action)

seccomp_load ::  Ptr CFilterCtx -> IO CInt
seccomp_load ctx = c_seccomp_load ctx

--  scmp_filter_ctx seccomp_init(uint32_t def_action);
foreign import ccall unsafe "seccomp_init"
    c_seccomp_init :: CULong -> IO (Ptr CFilterCtx)

foreign import ccall "seccomp_reset"
    c_seccomp_reset :: Ptr CFilterCtx -> CULong -> IO CInt

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

seccomp_export_pfc :: Ptr CFilterCtx -> Int -> IO CInt
seccomp_export_pfc ctx fd = c_seccomp_export_pfc ctx (fromIntegral fd)

--data ArgumentPosition = A0 | A1 | A2 | A3 | A4 | A5

data ArgCmpOp = NE | LT | LE | EQ | GE | GT | MASQUED_EQ Int
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
argCmpOpToCInt (MASQUED_EQ x) = #const SCMP_CMP_MASKED_EQ

instance Storable ArgCmp where
    sizeOf _ = #{size struct scmp_arg_cmp}
    alignment _ = alignment (undefined :: CInt)

    poke p cmp = do
        #{poke struct scmp_arg_cmp, arg} p $ argCmpPos cmp
        #{poke struct scmp_arg_cmp, op} p $ argCmpOpToCInt (argCmpOp cmp)
        #{poke struct scmp_arg_cmp, datum_a} p $ argCmpDatumA cmp
        #{poke struct scmp_arg_cmp, datum_b} p $ argCmpDatumB cmp

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

data SysCall =
      SCsocket --		-101
    | SCbind --		-102
    | SCconnect --		-103
    | SClisten --		-104
    | SCaccept --		-105
    | SCgetsockname --	-106
    | SCgetpeername --	-107
    | SCsocketpair --	-108
    | SCsend --		-109
    | SCrecv --		-110
    | SCsendto --		-111
    | SCrecvfrom --		-112
    | SCshutdown --		-113
    | SCsetsockopt --	-114
    | SCgetsockopt --	-115
    | SCsendmsg --		-116
    | SCrecvmsg --		-117
    | SCaccept4 --		-118
    | SCrecvmmsg --		-119
    | SCsendmmsg --		-120
    | SCsemop --		-201
    | SCsemget --		-202
    | SCsemctl --		-203
    | SCsemtimedop --	-204
    | SCmsgsnd --		-211
    | SCmsgrcv --		-212
    | SCmsgget --		-213
    | SCmsgctl --		-214
    | SCshmat --		-221
    | SCshmdt --		-222
    | SCshmget --		-223
    | SCshmctl --		-224
    | SCarch_prctl --	-10001
    | SCbdflush --		-10002
    | SCbreak --		-10003
    | SCchown32 --		-10004
    | SCepoll_ctl_old --	-10005
    | SCepoll_wait_old --	-10006
    | SCfadvise64_64 --	-10007
    | SCfchown32 --		-10008
    | SCfcntl64 --		-10009
    | SCfstat64 --		-10010
    | SCfstatat64 --		-10011
    | SCfstatfs64 --		-10012
    | SCftime --		-10013
    | SCftruncate64 --	-10014
    | SCgetegid32 --		-10015
    | SCgeteuid32 --		-10016
    | SCgetgid32 --		-10017
    | SCgetgroups32 --	-10018
    | SCgetresgid32 --	-10019
    | SCgetresuid32 --	-10020
    | SCgetuid32 --		-10021
    | SCgtty --		-10022
    | SCidle --		-10023
    | SCipc --		-10024
    | SClchown32 --		-10025
    | SC_llseek --		-10026
    | SClock --		-10027
    | SClstat64 --		-10028
    | SCmmap2 --		-10029
    | SCmpx --		-10030
    | SCnewfstatat --	-10031
    | SC_newselect --	-10032
    | SCnice --		-10033
    | SColdfstat --		-10034
    | SColdlstat --		-10035
    | SColdolduname --	-10036
    | SColdstat --		-10037
    | SColduname --		-10038
    | SCprof --		-10039
    | SCprofil --		-10040
    | SCreaddir --		-10041
    | SCsecurity --		-10042
    | SCsendfile64 --	-10043
    | SCsetfsgid32 --	-10044
    | SCsetfsuid32 --	-10045
    | SCsetgid32 --		-10046
    | SCsetgroups32 --	-10047
    | SCsetregid32 --	-10048
    | SCsetresgid32 --	-10049
    | SCsetresuid32 --	-10050
    | SCsetreuid32 --	-10051
    | SCsetuid32 --		-10052
    | SCsgetmask --		-10053
    | SCsigaction --		-10054
    | SCsignal --		-10055
    | SCsigpending --	-10056
    | SCsigprocmask --	-10057
    | SCsigreturn --		-10058
    | SCsigsuspend --	-10059
    | SCsocketcall --	-10060
    | SCssetmask --		-10061
    | SCstat64 --		-10062
    | SCstatfs64 --		-10063
    | SCstime --		-10064
    | SCstty --		-10065
    | SCtruncate64 --	-10066
    | SCtuxcall --		-10067
    | SCugetrlimit --	-10068
    | SCulimit --		-10069
    | SCumount --		-10070
    | SCvm86 --		-10071
    | SCvm86old --		-10072
    | SCwaitpid --		-10073
    | SCcreate_module --	-10074
    | SCget_kernel_syms --	-10075
    | SCget_thread_area --	-10076
    | SCnfsservctl --	-10077
    | SCquery_module --	-10078
    | SCset_thread_area --	-10079
    | SC_sysctl --		-10080
    | SCuselib --		-10081
    | SCvserver --		-10082
    | SCarm_fadvise64_64 --	-10083
    | SCarm_sync_file_range --	-10084
    | SCpciconfig_iobase --	-10086
    | SCpciconfig_read --	-10087
    | SCpciconfig_write --	-10088
    | SCsync_file_range2 --	-10089
    | SCsyscall --		-10090
    | SCafs_syscall --	-10091
    | SCfadvise64 --		-10092
    | SCgetpmsg --		-10093
    | SCioperm --		-10094
    | SCiopl --		-10095
    | SCmigrate_pages --	-10097
    | SCmodify_ldt --	-10098
    | SCputpmsg --		-10099
    | SCsync_file_range --	-10100
    | SCselect --		-10101
    | SCvfork --		-10102
    | SCcachectl --		-10103
    | SCcacheflush --	-10104
    | SCsysmips --		-10106
    | SCtimerfd --		-10107
    | SCtime --		-10108
    | SCgetrandom --		-10109
    | SCmemfd_create --	-10110
    | SCkexec_file_load --	-10111
    | SCsysfs --		-10145
    | SColdwait4 --		-10146
    | SCaccess --		-10147
    | SCalarm --		-10148
    | SCchmod --		-10149
    | SCchown --		-10150
    | SCcreat --		-10151
    | SCdup2 --		-10152
    | SCepoll_create --	-10153
    | SCepoll_wait --	-10154
    | SCeventfd --		-10155
    | SCfork --		-10156
    | SCfutimesat --		-10157
    | SCgetdents --		-10158
    | SCgetpgrp --		-10159
    | SCinotify_init --	-10160
    | SClchown --		-10161
    | SClink --		-10162
    | SClstat --		-10163
    | SCmkdir --		-10164
    | SCmknod --		-10165
    | SCopen --		-10166
    | SCpause --		-10167
    | SCpipe --		-10168
    | SCpoll --		-10169
    | SCreadlink --		-10170
    | SCrename --		-10171
    | SCrmdir --		-10172
    | SCsignalfd --		-10173
    | SCstat --		-10174
    | SCsymlink --		-10175
    | SCunlink --		-10176
    | SCustat --		-10177
    | SCutime --		-10178
    | SCutimes --		-10179
    | SCgetrlimit --		-10180
    | SCmmap --		-10181
    | SCbreakpoint --	-10182
    | SCset_tls --		-10183
    | SCusr26 --		-10184
    | SCusr32 --		-10185


#define hsc_signed_const(x...)      \
        hsc_printf ("(%lld)", (long long)(x));

sysCallToC :: SysCall -> CLong
sysCallToC x = case x of
    SCsocket -> #signed_const SCMP_SYS(socket)
    SCbind -> #signed_const SCMP_SYS(bind)
    SCconnect -> #signed_const SCMP_SYS(connect)
    SClisten -> #signed_const SCMP_SYS(listen)
    SCaccept -> #signed_const SCMP_SYS(accept)
    SCgetsockname -> #signed_const SCMP_SYS(getsockname)
    SCgetpeername -> #signed_const SCMP_SYS(getpeername)
    SCsocketpair -> #signed_const SCMP_SYS(socketpair)
    SCsend -> #signed_const SCMP_SYS(send)
    SCrecv -> #signed_const SCMP_SYS(recv)
    SCsendto -> #signed_const SCMP_SYS(sendto)
    SCrecvfrom -> #signed_const SCMP_SYS(recvfrom)
    SCshutdown -> #signed_const SCMP_SYS(shutdown)
    SCsetsockopt -> #signed_const SCMP_SYS(setsockopt)
    SCgetsockopt -> #signed_const SCMP_SYS(getsockopt)
    SCsendmsg -> #signed_const SCMP_SYS(sendmsg)
    SCrecvmsg -> #signed_const SCMP_SYS(recvmsg)
    SCaccept4 -> #signed_const SCMP_SYS(accept4)
    SCrecvmmsg -> #signed_const SCMP_SYS(recvmmsg)
    SCsendmmsg -> #signed_const SCMP_SYS(sendmmsg)
    SCsemop -> #signed_const SCMP_SYS(semop)
    SCsemget -> #signed_const SCMP_SYS(semget)
    SCsemctl -> #signed_const SCMP_SYS(semctl)
    SCsemtimedop -> #signed_const SCMP_SYS(semtimedop)
    SCmsgsnd -> #signed_const SCMP_SYS(msgsnd)
    SCmsgrcv -> #signed_const SCMP_SYS(msgrcv)
    SCmsgget -> #signed_const SCMP_SYS(msgget)
    SCmsgctl -> #signed_const SCMP_SYS(msgctl)
    SCshmat -> #signed_const SCMP_SYS(shmat)
    SCshmdt -> #signed_const SCMP_SYS(shmdt)
    SCshmget -> #signed_const SCMP_SYS(shmget)
    SCshmctl -> #signed_const SCMP_SYS(shmctl)
    SCarch_prctl -> #signed_const SCMP_SYS(arch_prctl)
    SCbdflush -> #signed_const SCMP_SYS(bdflush)
    SCbreak -> #signed_const SCMP_SYS(break)
    SCchown32 -> #signed_const SCMP_SYS(chown32)
    SCepoll_ctl_old -> #signed_const SCMP_SYS(epoll_ctl_old)
    SCepoll_wait_old -> #signed_const SCMP_SYS(epoll_wait_old)
    SCfadvise64_64 -> #signed_const SCMP_SYS(fadvise64_64)
    SCfchown32 -> #signed_const SCMP_SYS(fchown32)
    SCfcntl64 -> #signed_const SCMP_SYS(fcntl64)
    SCfstat64 -> #signed_const SCMP_SYS(fstat64)
    SCfstatat64 -> #signed_const SCMP_SYS(fstatat64)
    SCfstatfs64 -> #signed_const SCMP_SYS(fstatfs64)
    SCftime -> #signed_const SCMP_SYS(ftime)
    SCftruncate64 -> #signed_const SCMP_SYS(ftruncate64)
    SCgetegid32 -> #signed_const SCMP_SYS(getegid32)
    SCgeteuid32 -> #signed_const SCMP_SYS(geteuid32)
    SCgetgid32 -> #signed_const SCMP_SYS(getgid32)
    SCgetgroups32 -> #signed_const SCMP_SYS(getgroups32)
    SCgetresgid32 -> #signed_const SCMP_SYS(getresgid32)
    SCgetresuid32 -> #signed_const SCMP_SYS(getresuid32)
    SCgetuid32 -> #signed_const SCMP_SYS(getuid32)
    SCgtty -> #signed_const SCMP_SYS(gtty)
    SCidle -> #signed_const SCMP_SYS(idle)
    SCipc -> #signed_const SCMP_SYS(ipc)
    SClchown32 -> #signed_const SCMP_SYS(lchown32)
    SC_llseek -> #signed_const SCMP_SYS(_llseek)
    SClock -> #signed_const SCMP_SYS(lock)
    SClstat64 -> #signed_const SCMP_SYS(lstat64)
    SCmmap2 -> #signed_const SCMP_SYS(mmap2)
    SCmpx -> #signed_const SCMP_SYS(mpx)
    SCnewfstatat -> #signed_const SCMP_SYS(newfstatat)
    SC_newselect -> #signed_const SCMP_SYS(_newselect)
    SCnice -> #signed_const SCMP_SYS(nice)
    SColdfstat -> #signed_const SCMP_SYS(oldfstat)
    SColdlstat -> #signed_const SCMP_SYS(oldlstat)
    SColdolduname -> #signed_const SCMP_SYS(oldolduname)
    SColdstat -> #signed_const SCMP_SYS(oldstat)
    SColduname -> #signed_const SCMP_SYS(olduname)
    SCprof -> #signed_const SCMP_SYS(prof)
    SCprofil -> #signed_const SCMP_SYS(profil)
    SCreaddir -> #signed_const SCMP_SYS(readdir)
    SCsecurity -> #signed_const SCMP_SYS(security)
    SCsendfile64 -> #signed_const SCMP_SYS(sendfile64)
    SCsetfsgid32 -> #signed_const SCMP_SYS(setfsgid32)
    SCsetfsuid32 -> #signed_const SCMP_SYS(setfsuid32)
    SCsetgid32 -> #signed_const SCMP_SYS(setgid32)
    SCsetgroups32 -> #signed_const SCMP_SYS(setgroups32)
    SCsetregid32 -> #signed_const SCMP_SYS(setregid32)
    SCsetresgid32 -> #signed_const SCMP_SYS(setresgid32)
    SCsetresuid32 -> #signed_const SCMP_SYS(setresuid32)
    SCsetreuid32 -> #signed_const SCMP_SYS(setreuid32)
    SCsetuid32 -> #signed_const SCMP_SYS(setuid32)
    SCsgetmask -> #signed_const SCMP_SYS(sgetmask)
    SCsigaction -> #signed_const SCMP_SYS(sigaction)
    SCsignal -> #signed_const SCMP_SYS(signal)
    SCsigpending -> #signed_const SCMP_SYS(sigpending)
    SCsigprocmask -> #signed_const SCMP_SYS(sigprocmask)
    SCsigreturn -> #signed_const SCMP_SYS(sigreturn)
    SCsigsuspend -> #signed_const SCMP_SYS(sigsuspend)
    SCsocketcall -> #signed_const SCMP_SYS(socketcall)
    SCssetmask -> #signed_const SCMP_SYS(ssetmask)
    SCstat64 -> #signed_const SCMP_SYS(stat64)
    SCstatfs64 -> #signed_const SCMP_SYS(statfs64)
    SCstime -> #signed_const SCMP_SYS(stime)
    SCstty -> #signed_const SCMP_SYS(stty)
    SCtruncate64 -> #signed_const SCMP_SYS(truncate64)
    SCtuxcall -> #signed_const SCMP_SYS(tuxcall)
    SCugetrlimit -> #signed_const SCMP_SYS(ugetrlimit)
    SCulimit -> #signed_const SCMP_SYS(ulimit)
    SCumount -> #signed_const SCMP_SYS(umount)
    SCvm86 -> #signed_const SCMP_SYS(vm86)
    SCvm86old -> #signed_const SCMP_SYS(vm86old)
    SCwaitpid -> #signed_const SCMP_SYS(waitpid)
    SCcreate_module -> #signed_const SCMP_SYS(create_module)
    SCget_kernel_syms -> #signed_const SCMP_SYS(get_kernel_syms)
    SCget_thread_area -> #signed_const SCMP_SYS(get_thread_area)
    SCnfsservctl -> #signed_const SCMP_SYS(nfsservctl)
    SCquery_module -> #signed_const SCMP_SYS(query_module)
    SCset_thread_area -> #signed_const SCMP_SYS(set_thread_area)
    SC_sysctl -> #signed_const SCMP_SYS(_sysctl)
    SCuselib -> #signed_const SCMP_SYS(uselib)
    SCvserver -> #signed_const SCMP_SYS(vserver)
    SCarm_fadvise64_64 -> #signed_const SCMP_SYS(arm_fadvise64_64)
    SCarm_sync_file_range -> #signed_const SCMP_SYS(arm_sync_file_range)
    SCpciconfig_iobase -> #signed_const SCMP_SYS(pciconfig_iobase)
    SCpciconfig_read -> #signed_const SCMP_SYS(pciconfig_read)
    SCpciconfig_write -> #signed_const SCMP_SYS(pciconfig_write)
    SCsync_file_range2 -> #signed_const SCMP_SYS(sync_file_range2)
    SCsyscall -> #signed_const SCMP_SYS(syscall)
    SCafs_syscall -> #signed_const SCMP_SYS(afs_syscall)
    SCfadvise64 -> #signed_const SCMP_SYS(fadvise64)
    SCgetpmsg -> #signed_const SCMP_SYS(getpmsg)
    SCioperm -> #signed_const SCMP_SYS(ioperm)
    SCiopl -> #signed_const SCMP_SYS(iopl)
    SCmigrate_pages -> #signed_const SCMP_SYS(migrate_pages)
    SCmodify_ldt -> #signed_const SCMP_SYS(modify_ldt)
    SCputpmsg -> #signed_const SCMP_SYS(putpmsg)
    SCsync_file_range -> #signed_const SCMP_SYS(sync_file_range)
    SCselect -> #signed_const SCMP_SYS(select)
    SCvfork -> #signed_const SCMP_SYS(vfork)
    SCcachectl -> #signed_const SCMP_SYS(cachectl)
    SCcacheflush -> #signed_const SCMP_SYS(cacheflush)
    SCsysmips -> #signed_const SCMP_SYS(sysmips)
    SCtimerfd -> #signed_const SCMP_SYS(timerfd)
    SCtime -> #signed_const SCMP_SYS(time)
    SCgetrandom -> #signed_const SCMP_SYS(getrandom)
    SCmemfd_create -> #signed_const SCMP_SYS(memfd_create)
    SCkexec_file_load -> #signed_const SCMP_SYS(kexec_file_load)
    SCsysfs -> #signed_const SCMP_SYS(sysfs)
    SColdwait4 -> #signed_const SCMP_SYS(oldwait4)
    SCaccess -> #signed_const SCMP_SYS(access)
    SCalarm -> #signed_const SCMP_SYS(alarm)
    SCchmod -> #signed_const SCMP_SYS(chmod)
    SCchown -> #signed_const SCMP_SYS(chown)
    SCcreat -> #signed_const SCMP_SYS(creat)
    SCdup2 -> #signed_const SCMP_SYS(dup2)
    SCepoll_create -> #signed_const SCMP_SYS(epoll_create)
    SCepoll_wait -> #signed_const SCMP_SYS(epoll_wait)
    SCeventfd -> #signed_const SCMP_SYS(eventfd)
    SCfork -> #signed_const SCMP_SYS(fork)
    SCfutimesat -> #signed_const SCMP_SYS(futimesat)
    SCgetdents -> #signed_const SCMP_SYS(getdents)
    SCgetpgrp -> #signed_const SCMP_SYS(getpgrp)
    SCinotify_init -> #signed_const SCMP_SYS(inotify_init)
    SClchown -> #signed_const SCMP_SYS(lchown)
    SClink -> #signed_const SCMP_SYS(link)
    SClstat -> #signed_const SCMP_SYS(lstat)
    SCmkdir -> #signed_const SCMP_SYS(mkdir)
    SCmknod -> #signed_const SCMP_SYS(mknod)
    SCopen -> #signed_const SCMP_SYS(open)
    SCpause -> #signed_const SCMP_SYS(pause)
    SCpipe -> #signed_const SCMP_SYS(pipe)
    SCpoll -> #signed_const SCMP_SYS(poll)
    SCreadlink -> #signed_const SCMP_SYS(readlink)
    SCrename -> #signed_const SCMP_SYS(rename)
    SCrmdir -> #signed_const SCMP_SYS(rmdir)
    SCsignalfd -> #signed_const SCMP_SYS(signalfd)
    SCstat -> #signed_const SCMP_SYS(stat)
    SCsymlink -> #signed_const SCMP_SYS(symlink)
    SCunlink -> #signed_const SCMP_SYS(unlink)
    SCustat -> #signed_const SCMP_SYS(ustat)
    SCutime -> #signed_const SCMP_SYS(utime)
    SCutimes -> #signed_const SCMP_SYS(utimes)
    SCgetrlimit -> #signed_const SCMP_SYS(getrlimit)
    SCmmap -> #signed_const SCMP_SYS(mmap)
    SCbreakpoint -> #signed_const SCMP_SYS(breakpoint)
    SCset_tls -> #signed_const SCMP_SYS(set_tls)
    SCusr26 -> #signed_const SCMP_SYS(usr26)
    SCusr32 -> #signed_const SCMP_SYS(usr32)
