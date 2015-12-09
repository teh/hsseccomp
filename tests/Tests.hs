module Main where

import Test.Tasty
import Test.Tasty.HUnit
import qualified System.Linux.Seccomp as S
import Foreign.Ptr (nullPtr)
import System.Posix.Process (forkProcess, getProcessStatus, ProcessStatus(..))
import System.IO (openFile, IOMode(..))
import System.Posix.Signals (sigSYS)

main :: IO ()
main = defaultMain unitTests

unitTests :: TestTree
unitTests = testGroup "Unit tests"
  [ testCase "init" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        if ctx /= nullPtr then return () else assertFailure "seccomp_init returned 0"
  , testCase "kill on any open"  $ do
        assertTerminated killOnAnyOpen
  ]

killOnAnyOpen = do
    ctx <- S.seccomp_init S.SCMP_ACT_KILL
    _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCopen []
    S.seccomp_load ctx
    openFile "/dev/null" ReadMode
    return ()

assertTerminated :: IO () -> Assertion
assertTerminated f = do
    pid <- forkProcess f
    result <- getProcessStatus True False pid
    assertBool "didn't terminate" (result == Just (Terminated sigSYS False))
