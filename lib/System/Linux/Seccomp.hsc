{- |
Module      : System.Linux.Seccomp
Stability   : provisional
Portability : non-portable (requires Linux)

This module provides bindings libseccomp.

-}
module System.Linux.Seccomp
   ( seccomp_init
   , seccomp_reset
   , DefaultAction(..)
   ) where

import Foreign
import Foreign.C.Types

#include <seccomp.h>


data DefaultAction =
      SCMP_ACT_KILL
    | SCMP_ACT_TRAP
    | SCMP_ACT_ERRNO Int
    | SCMP_ACT_TRACE Int
    | SCMP_ACT_ALLOW

type FilterCtx = ()


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
actionToCInt :: DefaultAction -> CInt
actionToCInt SCMP_ACT_KILL = 0x00000000
actionToCInt SCMP_ACT_TRAP = 0x00030000
actionToCInt (SCMP_ACT_ERRNO x) = 0x00050000 .|. ((fromIntegral x) .&. 0x0000ffff)
actionToCInt (SCMP_ACT_TRACE x) = 0x7ff00000 .|. ((fromIntegral x) .&. 0x0000ffff)
actionToCInt SCMP_ACT_ALLOW = 0x7fff0000


seccomp_init :: DefaultAction -> IO (Ptr FilterCtx)
seccomp_init action = c_seccomp_init (actionToCInt action)

seccomp_reset :: Ptr FilterCtx -> DefaultAction -> IO CInt
seccomp_reset ctx action = c_seccomp_reset ctx (actionToCInt action)

--  scmp_filter_ctx seccomp_init(uint32_t def_action);
foreign import ccall unsafe "seccomp_init"
    c_seccomp_init :: CInt -> IO (Ptr FilterCtx)

foreign import ccall "seccomp_reset"
    c_seccomp_reset :: Ptr FilterCtx -> CInt -> IO CInt
