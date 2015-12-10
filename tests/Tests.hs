module Main where

import Foreign.Ptr (nullPtr)
import System.Posix.IO as IO
import System.Posix.Process (forkProcess, getProcessStatus, ProcessStatus(..))
import System.Posix.Signals (sigSYS)
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
  , testCase "kill on any open"  $ assertTerminated killOnAnyOpen
  , testCase "kill on write"  $ assertTerminated killOpenWrite
  , testCase "change priority" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        r <- S.seccomp_syscall_priority ctx S.SCopen 8
        assertBool "return code /= 0" (r == 0)
  ]

-- test export
-- S.seccomp_export_pfc ctx 2

killOnAnyOpen :: Assertion
killOnAnyOpen = do
    ctx <- S.seccomp_init S.SCMP_ACT_KILL
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCopen []
    _ <- S.seccomp_load ctx
    S.seccomp_release ctx
    _ <- IO.openFd "/dev/null" IO.ReadOnly Nothing IO.defaultFileFlags
    return ()

killOpenWrite :: Assertion
killOpenWrite = do
    ctx <- S.seccomp_init S.SCMP_ACT_ALLOW
    -- kill on write
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_KILL S.SCopen [S.ArgCmp 1 S.MASQUED_EQ 0x3 0x1]
    _ <- S.seccomp_load ctx
    S.seccomp_release ctx
    _ <- IO.openFd "/dev/null" IO.WriteOnly Nothing IO.defaultFileFlags
    return ()

assertTerminated :: IO () -> Assertion
assertTerminated f = do
    pid <- forkProcess f
    result <- getProcessStatus True False pid
    assertBool ("didn't terminate: " ++ show result) (result == Just (Terminated sigSYS False))
