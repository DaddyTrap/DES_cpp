#include "des.h"
#include <bitset>
#include <fstream>
#include <string>

using std::bitset;
using std::fstream;
using std::string;

template <size_t SOURCE_LENGTH, size_t TARGET_LENGTH>
bitset<TARGET_LENGTH> substitute(bitset<SOURCE_LENGTH> source, unsigned char sub_matrix[TARGET_LENGTH]) {
  bitset<TARGET_LENGTH> ret;
  for (int i = 0; i < TARGET_LENGTH; ++i) {
    ret[TARGET_LENGTH - 1 - i] = source[SOURCE_LENGTH - sub_matrix[i]];
  }
  return ret;
}

bitset<64> g_K;
bitset<48> g_K_i[16];

void left_shift(bitset<28> &cd, int num) {
  for (int i = 0; i < num; ++i) {
    bool temp = cd[27];
    cd <<= 1;
    cd[0] = temp;
  }
}

unsigned char left_shift_num[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

void key_dispatch(bitset<64> key) {
  // 1. PC-1置换
  bitset<56> sub_res = substitute<64, 56>(key, PC_1);
  // 获取C_0 D_0
  bitset<28> C_i, D_i;
  for (int i = 28; i < 56; ++i) C_i[i - 28] = sub_res[i];
  for (int i = 0; i < 28; ++i) D_i[i] = sub_res[i];

  for (int i = 0; i < 16; ++i) {
    // 2. 循环左移
    left_shift(C_i, left_shift_num[i]);
    left_shift(D_i, left_shift_num[i]);
    bitset<56> combined_set;
    for (int i = 0; i < 28; ++i) combined_set[i] = D_i[i];
    for (int i = 28; i < 56; ++i) combined_set[i] = C_i[i - 28];
    // 3. PC-2置换
    g_K_i[i] = substitute<56, 48>(combined_set, PC_2);
  }
}

bitset<32> f(bitset<32> R, bitset<48> K_i) {
  // 1. E扩展
  bitset<48> ex = substitute<32, 48>(R, EXTEND);

  // 2. ex与K_i按位异或
  ex ^= K_i;
  
  // 3. 分成8个分组，代入S-Box进行6-4转换
  unsigned int res = 0;
  for (int i = 0; i < 8; ++i) {
    int x = ex[48 - i * 6 - 1] * 2 + ex[48 - i * 6 - 6];
    int y = ex[48 - i * 6 - 2] * 8 + ex[48 - i * 6 - 3] * 4 +
            ex[48 - i * 6 - 4] * 2 + ex[48 - i * 6 - 5];
    // 4. 合并成32位的串
    res ^= S_BOX[i][x][y] << (7 - i) * 4;
  }
  bitset<32> res_bitset(res);
  
  // 5. P置换
  return substitute<32, 32>(res_bitset, P);
}

bitset<64> des_encrypt(bitset<64> data, bitset<64> key) {
  bitset<64> mid;
  // 1. IP置换
  mid = substitute<64, 64>(data, IP);
  
  // 2. 16次迭代
  key_dispatch(key);  // 先做密钥调度
  bitset<32> L_i, R_i, swap_temp;
  // 获取L_0和R_0
  for (int i = 32; i < 64; ++i) L_i[i - 32] = mid[i];
  for (int i = 0; i < 32; ++i) R_i[i] = mid[i];
  for (int i = 0; i < 16; ++i) {
    swap_temp = R_i;
    R_i = L_i ^ f(R_i, g_K_i[i]);
    L_i = swap_temp;
  }
  // 输出R_16 | L_16
  for (int i = 32; i < 64; ++i) mid[i] = R_i[i - 32];
  for (int i = 0; i < 32; ++i) mid[i] = L_i[i];
  // 3. IP_inv置换
  mid = substitute<64, 64>(mid, IP_inv);
  return mid;
}

bitset<64> des_decrypt(bitset<64> data, bitset<64> key) {
  bitset<64> mid;
  // 1. IP置换
  mid = substitute<64, 64>(data, IP);

  // 2. 16次迭代
  key_dispatch(key);  // 先做密钥调度
  bitset<32> L_i, R_i, swap_temp;
  // 获取L_0和R_0
  for (int i = 32; i < 64; ++i) L_i[i - 32] = mid[i];
  for (int i = 0; i < 32; ++i) R_i[i] = mid[i];
  for (int i = 0; i < 16; ++i) {
    swap_temp = R_i;
    R_i = L_i ^ f(R_i, g_K_i[15 - i]);  // 16 -> 1，解密
    L_i = swap_temp;
  }
  // 输出R_16 | L_16
  for (int i = 32; i < 64; ++i) mid[i] = R_i[i - 32];
  for (int i = 0; i < 32; ++i) mid[i] = L_i[i];
  
  // 3. IP_inv置换
  mid = substitute<64, 64>(mid, IP_inv);
  
  return mid;
}

bitset<64> stringToBitset(string str) {
  unsigned long long val = 0;
  if (str.length() < 8) {
    for (int i = str.length() - 1; i >= 0; --i) {
      val <<= 8;
      val ^= str[i];
    }
    val <<= (8 - str.length()) * 8;
  } else {
    for (int i = 7; i >= 0; --i) {
      val <<= 8;
      val ^= str[i];
    }
  }
  return bitset<64>(val);
}

int main() {
  string m = "abcdefgh";
  string k = "12345678";
  
  auto m_bitset = stringToBitset(m);
  auto k_bitset = stringToBitset(k);
  
  auto cipher = des_encrypt(m_bitset, k_bitset);
  auto plain = des_decrypt(cipher, k_bitset);
  
  fstream file;
  file.open("test.txt", std::ios::binary | std::ios::out);
  file.write((char *)&plain, sizeof(plain));
  file.close();

  return 0;
}
