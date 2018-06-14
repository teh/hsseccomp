module Main where

import Foreign.Ptr (nullPtr)
import System.Posix.IO as PosixIO
import System.Posix.Process (forkProcess, getProcessStatus, ProcessStatus(..))
import System.Posix.Signals (sigSYS)
import System.Exit (exitFailure, exitSuccess, ExitCode(..))
import qualified Control.Exception (catch, SomeException)
import qualified System.IO
import qualified Foreign.C.Error as ErrNo
import Control.Monad (when)
import Test.Tasty
import Test.Tasty.HUnit
import qualified System.Linux.Seccomp as S

main :: IO ()
main = defaultMain unitTests

unitTests :: TestTree
unitTests = testGroup "Unit tests"
  [ testCase "init" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        if ctx /= nullPtr then return () else assertFailure "seccomp_init returned 0"
  , testCase "allow open"  $ assertExitSuccess allowOpen
  , testCase "allow writing to only stdout and stderr"  $ assertExitSuccess allowStdOutStdErr
  , testCase "kill on open for write"  $ assertTerminated killOpenWrite
  , testCase "setting errno instead of killing"  $ assertExitSuccess actErrno
  , testCase "change priority" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        r <- S.seccomp_syscall_priority ctx S.SCopen 8
        assertBool "return code /= 0" (r == 0)
  ]


-- test export
-- S.seccomp_export_pfc ctx 2

whitelistHaskellRuntimeCalls :: S.FilterContext -> IO ()
--TODO check return values in error monad?
whitelistHaskellRuntimeCalls ctx = do
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCclock_gettime []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCrt_sigprocmask []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCrt_sigaction []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCrt_sigreturn []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCtimer_settime []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCtimer_delete []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCclock_gettime []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCexit_group []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCselect []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCpoll []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCgetrusage []
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCpause []
    -- TODO no idea what haskell is doing here. I guess it tries to find out whether stdout is an attached terminal
    -- uncomment when needed
    --_ <- Seccomp.seccomp_rule_add_array ctx Seccomp.SCMP_ACT_ALLOW Seccomp.SCioctl [Seccomp.ArgCmp 0 Seccomp.EQ 1 43, Seccomp.ArgCmp 1 Seccomp.EQ 0x5401 43]
    --_ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCshmctl []
    -- only allow write for stdout (fd 1)
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCwrite [S.ArgCmp 0 S.EQ 1 43] -- TODO what is argCmpDatumB (here: 43)?
    --_ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCprctl []
    return ()


allowOpen :: Assertion
allowOpen = do
    ctx <- S.seccomp_init S.SCMP_ACT_KILL
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCopenat []

    -- TODO it's annoying that we need to white list so many syscalls
    -- for the Haskell runtime but I can't think of a better solution
    -- ATM.
    whitelistHaskellRuntimeCalls ctx
    _ <- S.seccomp_load ctx
    _ <- PosixIO.openFd "/dev/null" PosixIO.ReadOnly Nothing PosixIO.defaultFileFlags
    S.seccomp_release ctx
    putStrLn "Hello World, this should be allowed"
    return ()

allowStdOutStdErr :: Assertion
allowStdOutStdErr = do
    ctx <- S.seccomp_init S.SCMP_ACT_KILL
    whitelistHaskellRuntimeCalls ctx
    -- allow write for stderr (fd 2)
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCwrite [S.ArgCmp 0 S.EQ 2 43] -- TODO what is argCmpDatumB (here: 43)?
    _ <- S.seccomp_load ctx
    S.seccomp_release ctx
    putStrLn "Hello World, this should be allowed"
    System.IO.hPutStrLn System.IO.stdout "This must also work"
    System.IO.hPutStrLn System.IO.stderr "This must also work"
    return ()
 

killOpenWrite :: Assertion
killOpenWrite = do
    ctx <- S.seccomp_init S.SCMP_ACT_ALLOW
    -- kill on write
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_KILL S.SCopenat [S.ArgCmp 2 S.MASQUED_EQ 0x3 0x1]
    _ <- S.seccomp_load ctx
    S.seccomp_release ctx
    _ <- PosixIO.openFd "/dev/null" PosixIO.WriteOnly Nothing PosixIO.defaultFileFlags
    return ()

actErrno :: Assertion
actErrno = do
    ErrNo.resetErrno
    -- trying to capture the syscall that should fail with an errno we can test
    ctx <- S.seccomp_init (S.SCMP_ACT_ERRNO 42)
    whitelistHaskellRuntimeCalls ctx
    res <- S.seccomp_load ctx
    S.seccomp_release ctx
    when (res /= 0) exitFailure
    -- triggering prohibited action
    _ <- Control.Exception.catch (System.IO.openFile "/dev/null" System.IO.ReadMode) $ \e -> do
            putStrLn ("caugth error: " ++ show (e::Control.Exception.SomeException))
            ErrNo.Errno errno <- ErrNo.getErrno
            if (errno == 42)
            then exitSuccess
            else (do
                    putStrLn ("unexpected errno: " ++ show errno)
                    exitFailure
                  )
            -- return dummy handle to make it compile. not reached
            return System.IO.stdin
    putStrLn "unreachable"
    exitFailure
    return ()


assertExitSuccess :: IO () -> Assertion
assertExitSuccess f = do
    pid <- forkProcess f
    result <- getProcessStatus True False pid
    assertBool ("unexpected terminate: " ++ show result) (result == Just (Exited ExitSuccess))


assertTerminated :: IO () -> Assertion
assertTerminated f = do
    pid <- forkProcess f
    result <- getProcessStatus True False pid
    assertBool ("didn't terminate: " ++ show result) (result == Just (Terminated sigSYS False)
                                                      || result == Just (Terminated sigSYS True))
