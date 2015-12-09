with (import <nixpkgs> {}).pkgs;
let pkg = haskellPackages.callPackage
            ({ mkDerivation, base, stdenv, libseccomp }:
             mkDerivation {
               pname = "hsseccomp";
               version = "0.1.0.0";
               src = ./.;
               buildDepends = [ base libseccomp ];
               description = "Haskell bindings to libseccomp";
               shellHook = ''
               export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${libseccomp}/lib
               '';
               license = stdenv.lib.licenses.asl20;
             }) {};
in
  pkg.env
