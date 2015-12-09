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
   , ArgCmp(..)
   , ArgCmpOp(..)
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

instance Storable ArgCmp where
    sizeOf _ = #{size struct scmp_arg_cmp}
    alignment _ = alignment (undefined :: CInt)

    peek = undefined -- Not needed, libseccomp has its own pretty printer
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


sysCallToC :: SysCall -> CLong
sysCallToC x = case x of
    SCsocket -> #const SCMP_SYS(socket)
    SCbind -> #const SCMP_SYS(bind)
    SCconnect -> #const SCMP_SYS(connect)
    SClisten -> #const SCMP_SYS(listen)
    SCaccept -> #const SCMP_SYS(accept)
    SCgetsockname -> #const SCMP_SYS(getsockname)
    SCgetpeername -> #const SCMP_SYS(getpeername)
    SCsocketpair -> #const SCMP_SYS(socketpair)
    SCsend -> #const SCMP_SYS(send)
    SCrecv -> #const SCMP_SYS(recv)
    SCsendto -> #const SCMP_SYS(sendto)
    SCrecvfrom -> #const SCMP_SYS(recvfrom)
    SCshutdown -> #const SCMP_SYS(shutdown)
    SCsetsockopt -> #const SCMP_SYS(setsockopt)
    SCgetsockopt -> #const SCMP_SYS(getsockopt)
    SCsendmsg -> #const SCMP_SYS(sendmsg)
    SCrecvmsg -> #const SCMP_SYS(recvmsg)
    SCaccept4 -> #const SCMP_SYS(accept4)
    SCrecvmmsg -> #const SCMP_SYS(recvmmsg)
    SCsendmmsg -> #const SCMP_SYS(sendmmsg)
    SCsemop -> #const SCMP_SYS(semop)
    SCsemget -> #const SCMP_SYS(semget)
    SCsemctl -> #const SCMP_SYS(semctl)
    SCsemtimedop -> #const SCMP_SYS(semtimedop)
    SCmsgsnd -> #const SCMP_SYS(msgsnd)
    SCmsgrcv -> #const SCMP_SYS(msgrcv)
    SCmsgget -> #const SCMP_SYS(msgget)
    SCmsgctl -> #const SCMP_SYS(msgctl)
    SCshmat -> #const SCMP_SYS(shmat)
    SCshmdt -> #const SCMP_SYS(shmdt)
    SCshmget -> #const SCMP_SYS(shmget)
    SCshmctl -> #const SCMP_SYS(shmctl)
    SCarch_prctl -> #const SCMP_SYS(arch_prctl)
    SCbdflush -> #const SCMP_SYS(bdflush)
    SCbreak -> #const SCMP_SYS(break)
    SCchown32 -> #const SCMP_SYS(chown32)
    SCepoll_ctl_old -> #const SCMP_SYS(epoll_ctl_old)
    SCepoll_wait_old -> #const SCMP_SYS(epoll_wait_old)
    SCfadvise64_64 -> #const SCMP_SYS(fadvise64_64)
    SCfchown32 -> #const SCMP_SYS(fchown32)
    SCfcntl64 -> #const SCMP_SYS(fcntl64)
    SCfstat64 -> #const SCMP_SYS(fstat64)
    SCfstatat64 -> #const SCMP_SYS(fstatat64)
    SCfstatfs64 -> #const SCMP_SYS(fstatfs64)
    SCftime -> #const SCMP_SYS(ftime)
    SCftruncate64 -> #const SCMP_SYS(ftruncate64)
    SCgetegid32 -> #const SCMP_SYS(getegid32)
    SCgeteuid32 -> #const SCMP_SYS(geteuid32)
    SCgetgid32 -> #const SCMP_SYS(getgid32)
    SCgetgroups32 -> #const SCMP_SYS(getgroups32)
    SCgetresgid32 -> #const SCMP_SYS(getresgid32)
    SCgetresuid32 -> #const SCMP_SYS(getresuid32)
    SCgetuid32 -> #const SCMP_SYS(getuid32)
    SCgtty -> #const SCMP_SYS(gtty)
    SCidle -> #const SCMP_SYS(idle)
    SCipc -> #const SCMP_SYS(ipc)
    SClchown32 -> #const SCMP_SYS(lchown32)
    SC_llseek -> #const SCMP_SYS(_llseek)
    SClock -> #const SCMP_SYS(lock)
    SClstat64 -> #const SCMP_SYS(lstat64)
    SCmmap2 -> #const SCMP_SYS(mmap2)
    SCmpx -> #const SCMP_SYS(mpx)
    SCnewfstatat -> #const SCMP_SYS(newfstatat)
    SC_newselect -> #const SCMP_SYS(_newselect)
    SCnice -> #const SCMP_SYS(nice)
    SColdfstat -> #const SCMP_SYS(oldfstat)
    SColdlstat -> #const SCMP_SYS(oldlstat)
    SColdolduname -> #const SCMP_SYS(oldolduname)
    SColdstat -> #const SCMP_SYS(oldstat)
    SColduname -> #const SCMP_SYS(olduname)
    SCprof -> #const SCMP_SYS(prof)
    SCprofil -> #const SCMP_SYS(profil)
    SCreaddir -> #const SCMP_SYS(readdir)
    SCsecurity -> #const SCMP_SYS(security)
    SCsendfile64 -> #const SCMP_SYS(sendfile64)
    SCsetfsgid32 -> #const SCMP_SYS(setfsgid32)
    SCsetfsuid32 -> #const SCMP_SYS(setfsuid32)
    SCsetgid32 -> #const SCMP_SYS(setgid32)
    SCsetgroups32 -> #const SCMP_SYS(setgroups32)
    SCsetregid32 -> #const SCMP_SYS(setregid32)
    SCsetresgid32 -> #const SCMP_SYS(setresgid32)
    SCsetresuid32 -> #const SCMP_SYS(setresuid32)
    SCsetreuid32 -> #const SCMP_SYS(setreuid32)
    SCsetuid32 -> #const SCMP_SYS(setuid32)
    SCsgetmask -> #const SCMP_SYS(sgetmask)
    SCsigaction -> #const SCMP_SYS(sigaction)
    SCsignal -> #const SCMP_SYS(signal)
    SCsigpending -> #const SCMP_SYS(sigpending)
    SCsigprocmask -> #const SCMP_SYS(sigprocmask)
    SCsigreturn -> #const SCMP_SYS(sigreturn)
    SCsigsuspend -> #const SCMP_SYS(sigsuspend)
    SCsocketcall -> #const SCMP_SYS(socketcall)
    SCssetmask -> #const SCMP_SYS(ssetmask)
    SCstat64 -> #const SCMP_SYS(stat64)
    SCstatfs64 -> #const SCMP_SYS(statfs64)
    SCstime -> #const SCMP_SYS(stime)
    SCstty -> #const SCMP_SYS(stty)
    SCtruncate64 -> #const SCMP_SYS(truncate64)
    SCtuxcall -> #const SCMP_SYS(tuxcall)
    SCugetrlimit -> #const SCMP_SYS(ugetrlimit)
    SCulimit -> #const SCMP_SYS(ulimit)
    SCumount -> #const SCMP_SYS(umount)
    SCvm86 -> #const SCMP_SYS(vm86)
    SCvm86old -> #const SCMP_SYS(vm86old)
    SCwaitpid -> #const SCMP_SYS(waitpid)
    SCcreate_module -> #const SCMP_SYS(create_module)
    SCget_kernel_syms -> #const SCMP_SYS(get_kernel_syms)
    SCget_thread_area -> #const SCMP_SYS(get_thread_area)
    SCnfsservctl -> #const SCMP_SYS(nfsservctl)
    SCquery_module -> #const SCMP_SYS(query_module)
    SCset_thread_area -> #const SCMP_SYS(set_thread_area)
    SC_sysctl -> #const SCMP_SYS(_sysctl)
    SCuselib -> #const SCMP_SYS(uselib)
    SCvserver -> #const SCMP_SYS(vserver)
    SCarm_fadvise64_64 -> #const SCMP_SYS(arm_fadvise64_64)
    SCarm_sync_file_range -> #const SCMP_SYS(arm_sync_file_range)
    SCpciconfig_iobase -> #const SCMP_SYS(pciconfig_iobase)
    SCpciconfig_read -> #const SCMP_SYS(pciconfig_read)
    SCpciconfig_write -> #const SCMP_SYS(pciconfig_write)
    SCsync_file_range2 -> #const SCMP_SYS(sync_file_range2)
    SCsyscall -> #const SCMP_SYS(syscall)
    SCafs_syscall -> #const SCMP_SYS(afs_syscall)
    SCfadvise64 -> #const SCMP_SYS(fadvise64)
    SCgetpmsg -> #const SCMP_SYS(getpmsg)
    SCioperm -> #const SCMP_SYS(ioperm)
    SCiopl -> #const SCMP_SYS(iopl)
    SCmigrate_pages -> #const SCMP_SYS(migrate_pages)
    SCmodify_ldt -> #const SCMP_SYS(modify_ldt)
    SCputpmsg -> #const SCMP_SYS(putpmsg)
    SCsync_file_range -> #const SCMP_SYS(sync_file_range)
    SCselect -> #const SCMP_SYS(select)
    SCvfork -> #const SCMP_SYS(vfork)
    SCcachectl -> #const SCMP_SYS(cachectl)
    SCcacheflush -> #const SCMP_SYS(cacheflush)
    SCsysmips -> #const SCMP_SYS(sysmips)
    SCtimerfd -> #const SCMP_SYS(timerfd)
    SCtime -> #const SCMP_SYS(time)
    SCgetrandom -> #const SCMP_SYS(getrandom)
    SCmemfd_create -> #const SCMP_SYS(memfd_create)
    SCkexec_file_load -> #const SCMP_SYS(kexec_file_load)
    SCsysfs -> #const SCMP_SYS(sysfs)
    SColdwait4 -> #const SCMP_SYS(oldwait4)
    SCaccess -> #const SCMP_SYS(access)
    SCalarm -> #const SCMP_SYS(alarm)
    SCchmod -> #const SCMP_SYS(chmod)
    SCchown -> #const SCMP_SYS(chown)
    SCcreat -> #const SCMP_SYS(creat)
    SCdup2 -> #const SCMP_SYS(dup2)
    SCepoll_create -> #const SCMP_SYS(epoll_create)
    SCepoll_wait -> #const SCMP_SYS(epoll_wait)
    SCeventfd -> #const SCMP_SYS(eventfd)
    SCfork -> #const SCMP_SYS(fork)
    SCfutimesat -> #const SCMP_SYS(futimesat)
    SCgetdents -> #const SCMP_SYS(getdents)
    SCgetpgrp -> #const SCMP_SYS(getpgrp)
    SCinotify_init -> #const SCMP_SYS(inotify_init)
    SClchown -> #const SCMP_SYS(lchown)
    SClink -> #const SCMP_SYS(link)
    SClstat -> #const SCMP_SYS(lstat)
    SCmkdir -> #const SCMP_SYS(mkdir)
    SCmknod -> #const SCMP_SYS(mknod)
    SCopen -> #const SCMP_SYS(open)
    SCpause -> #const SCMP_SYS(pause)
    SCpipe -> #const SCMP_SYS(pipe)
    SCpoll -> #const SCMP_SYS(poll)
    SCreadlink -> #const SCMP_SYS(readlink)
    SCrename -> #const SCMP_SYS(rename)
    SCrmdir -> #const SCMP_SYS(rmdir)
    SCsignalfd -> #const SCMP_SYS(signalfd)
    SCstat -> #const SCMP_SYS(stat)
    SCsymlink -> #const SCMP_SYS(symlink)
    SCunlink -> #const SCMP_SYS(unlink)
    SCustat -> #const SCMP_SYS(ustat)
    SCutime -> #const SCMP_SYS(utime)
    SCutimes -> #const SCMP_SYS(utimes)
    SCgetrlimit -> #const SCMP_SYS(getrlimit)
    SCmmap -> #const SCMP_SYS(mmap)
    SCbreakpoint -> #const SCMP_SYS(breakpoint)
    SCset_tls -> #const SCMP_SYS(set_tls)
    SCusr26 -> #const SCMP_SYS(usr26)
    SCusr32 -> #const SCMP_SYS(usr32)
