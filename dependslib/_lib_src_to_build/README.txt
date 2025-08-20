------------------
zlib-1.2.8
------------------
Build as zlibstatic.lib

------------------
openssl-1.0.2  
------------------
Must be build and installed to [c or d]:\lib\installed\openssl
perl Configure VC-WIN32 --prefix=d:\LIB\installed\openssl no-asm no-ec_nistp_64_gcc_128 no-gmp no-jpake no-krb5 no-libunbound \
no-md2 no-rc5 no-rfc3779 no-capieng no-sctp no-shared no-ssl-trace no-store no-unit-test no-zlib no-zlib-dynamic

copy D:/LIB/installed/libzip/include and /lib into lib/libs/openssl/

------------------
libzip 
------------------
// Windows cmake's arguments 
mkdir build & cd build
cmake -G"Ninja" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=D:/LIB/installed/libzip -DENABLE_BZIP2=OFF -DENABLE_WINDOWS_CRYPTO=OFF \
-DZLIB_INCLUDE_DIR=D:/LIB/installed/zlib/include -DZLIB_LIBRARY=D:/LIB/installed/zlib/lib/zlibstatic.lib ..
cmake --build .
cmake --install .
copy D:/LIB/installed/libzip/include and /lib into lib/libs/libzip/

------------------
libssh2 
------------------
// Windows cmake's arguments 
mkdir build & cd build
cmake -G"Ninja" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=D:/LIB/installed/libssh2 -DCRYPTO_BACKEND=OpenSSL -DENABLE_ZLIB_COMPRESSION=ON \
      -DOPENSSL_ROOT_DIR=D:/LIB/installed/openssl/ -DZLIB_INCLUDE_DIR=D:/LIB/installed/zlib/include -DZLIB_LIBRARY=D:/LIB/installed/zlib/lib/zlibstatic.lib ..
cmake --build .
cmake --install .
copy D:/LIB/installed/libssh2/include and /lib into lib/libs/libssh2/

Alternative build method with NMake:
nmake OPENSSLINC=D:/LIB/installed/openssl/include OPENSSLLIB=D:/LIB/installed/openssl/lib WITH_ZLB=1 BUILD_STATIC_LIB=1 -f NMakefile

------------------
curl-7.47.1
------------------
Must be build and installed to d:\lib\installed\curl
cmake -G"Ninja" -DCURL_STATICLIB=ON -DCURL_DISABLE_LDAP=ON  -DCMAKE_BUILD_TYPE=Release \
-DUSE_OPENSSL=ON -DUSE_WINDOWS_SSPI=OFF -DCURL_ZLIB=ON -DCMAKE_USE_OPENSSL=ON \
-DOPENSSL_ROOT_DIR=../../openssl  -DCMAKE_INSTALL_PREFIX=D:/LIB/installed/curl \
-DLibSSH2_DIR=../../libssh2/lib/cmake/libssh2  -DZLIB_INCLUDE_DIR=D:/LIB/installed/zlib/include -DZLIB_LIBRARY=D:/LIB/installed/zlib/lib/zlibstatic.lib .. 

Alternative build method with NMake:
binary lib need to be placed into debug and release lib foldes of the solution
curl-7.47.1\winbuild>nmake /f Makefile.vc mode=dll VC=8 WITH_SSL=static WITH_ZLIB=static WITH_SSH2=static ENABLE_IPV6=yes ENABLE_SSPI=no ENABLE_IDN=no ENABLE_WINSSL=no GEN_PDB=yes

------------------
botan-2.12.1
------------------
Generate amalgamation files botan_all.h, botan_all.cpp, botan_all_internal.h with botan's configure.py script. 
configure.py --cpu=x86_32  --cc=msvc --verbose --disable-shared --no-autoload --enable-modules=idea,hex,modes,ofb,ctr,filters --amalgamation

------------------
cpr
------------------
cmake -G"Ninja" -DCURL_STATICLIB=ON -DBUILD_CPR_TESTS=OFF -DUSE_SYSTEM_CURL=ON -DCMAKE_BUILD_TYPE=Release -DUSE_OPENSSL=ON -DCURL_ZLIB=ON \
-DCMAKE_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR=../../openssl  -DCMAKE_INSTALL_PREFIX=D:/LIB/installed/cpr 
-DCURL_INCLUDE_DIR=../../../curl/include -DCURL_LIBRARY=../../../curl/lib  
-DZLIB_INCLUDE_DIR=D:/LIB/installed/zlib/include -DZLIB_LIBRARY=D:/LIB/installed/zlib/lib/zlibstatic.lib ..

------------------
curlpp-0.8.1
------------------
cmake -G"Ninja" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../../../curlpp -DCURL_INCLUDE_DIR=../../../curl/include -DCURL_LIBRARY=../../../curl/lib/libcurl -DCURL_STATICLIB=ON ..
cmake --build .
cmake --install .

------------------
gtest
------------------
cmake -G"Ninja" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF  -DCMAKE_INSTALL_PREFIX=../../../gtest -DBUILD_GMOCK=ON -Dgtest_force_shared_crt=ON ..
cmake --build .
cmake --install .
cmake -G"Ninja" -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF  -DCMAKE_INSTALL_PREFIX=../../../gtest -DBUILD_GMOCK=ON -Dgtest_force_shared_crt=ON -DCMAKE_DEBUG_POSTFIX=d ..
cmake --build .
cmake --install .

------------------
tinyxml2
------------------
Use AS IS .cpp & .h files

------------------
gsoap
------------------
Use AS IS .cpp & .h files

------------------
sqlite3
------------------
Use AS IS .cpp & .h files of amalgamation from sqlite source

------------------
libKISSlog
------------------
Use AS .hpp files 
Source libKISSlog\src\kisslog-mt-static.cpp is need to be included into projects


