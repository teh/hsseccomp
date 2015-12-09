module Main where

import Test.Tasty
import Test.Tasty.HUnit
import qualified System.Linux.Seccomp as S
import Foreign.Ptr (nullPtr)
import System.Posix.Process (forkProcess, getProcessStatus)
import System.IO (openFile, IOMode(..))

main :: IO ()
main = defaultMain unitTests

unitTests :: TestTree
unitTests = testGroup "Unit tests"
  [ testCase "init" $ do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        if ctx /= nullPtr then return () else assertFailure "seccomp_init returned 0"
  , testFork
  ]

testFork :: TestTree
testFork = testCase "kill fork" $ do
    pid <- forkProcess tc
    r <- getProcessStatus True False pid
    print r
    return ()
  where
    tc = do
        ctx <- S.seccomp_init S.SCMP_ACT_KILL
        _ <- S.seccomp_rule_add_array ctx S.SCMP_ACT_ALLOW S.SCopen []
        S.seccomp_load ctx
        openFile "/dev/null" ReadMode
        return ()
