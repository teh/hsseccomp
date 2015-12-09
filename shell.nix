with (import <nixpkgs> {}).pkgs;
let pkg = haskellPackages.callPackage
            ({ mkDerivation, base, stdenv, libseccomp, tasty, tasty-hunit, unix }:
             mkDerivation {
               pname = "hsseccomp";
               version = "0.1.0.0";
               src = ./.;
               buildDepends = [ base libseccomp tasty tasty-hunit unix ];
               description = "Haskell bindings to libseccomp";
               shellHook = ''
               export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${libseccomp}/lib
               '';
               license = stdenv.lib.licenses.lgpl;
             }) {};
in
  pkg.env
