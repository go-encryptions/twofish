// one.cpp times Botan's Twofish on 1 KiB (64 blocks) two ways, so that the
// per-block Encrypt/Decrypt of this module can be compared like for like:
//
//	n   one encrypt_n/decrypt_n call over 64 blocks (what `botan speed` does;
//	    twofish.cpp then runs two blocks interleaved, and the out-of-order core
//	    overlaps consecutive pairs);
//	one 64 calls of one block each (twofish.cpp's single-block tail, the same
//	    shape as 64 calls of cipher.Block.Encrypt).
//
// Usage: one <n|one> <encrypt|decrypt>; prints microseconds per 1 KiB.
// Build: c++ -std=c++20 -O2 -I<botan include> one.cpp -lbotan-3 -o one
#include <botan/block_cipher.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

int main(int argc, char** argv) {
   if(argc != 3) {
      return 2;
   }
   if((std::strcmp(argv[1], "one") != 0 && std::strcmp(argv[1], "n") != 0) ||
      (std::strcmp(argv[2], "encrypt") != 0 && std::strcmp(argv[2], "decrypt") != 0)) {
      return 2;
   }
   const bool one = std::strcmp(argv[1], "one") == 0;
   const bool dec = std::strcmp(argv[2], "decrypt") == 0;
   auto c = Botan::BlockCipher::create_or_throw("Twofish");
   const std::vector<uint8_t> key(32, 7);
   c->set_key(key);
   std::vector<uint8_t> in(1024, 1), out(1024);
   auto once = [&] {
      if(!one) {
         dec ? c->decrypt_n(in.data(), out.data(), 64) : c->encrypt_n(in.data(), out.data(), 64);
         return;
      }
      for(int i = 0; i < 64; i++) {
         dec ? c->decrypt_n(in.data() + 16 * i, out.data() + 16 * i, 1) : c->encrypt_n(in.data() + 16 * i, out.data() + 16 * i, 1);
      }
   };
   double best = 1e30;
   for(int r = 0; r < 25; r++) {
      const int N = 20000;
      const auto t0 = std::chrono::steady_clock::now();
      for(int i = 0; i < N; i++) {
         once();
      }
      const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / N;
      if(us < best) {
         best = us;
      }
   }
   std::printf("%.4f\n", best);
   return 0;
}
